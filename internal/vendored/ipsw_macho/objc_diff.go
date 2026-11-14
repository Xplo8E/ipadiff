// objc_diff.go is vendored from
// github.com/blacktop/ipsw/internal/commands/macho/objc_diff.go at commit
// 27f1f0a5b30338fb6406e52e2c0d62f98f9ab16e. Adapted: the ObjC wrapper type and
// its ObjcConfig (DSC cache, imported-framework deps, demangle, addrs) are
// dropped — ipadiff diffs standalone IPA binaries, so the model builders work
// directly on *macho.File. DiffObjC replaces the (o *ObjC) Diff method and
// returns the raw diff body without the "# ObjC diff" header and code fence;
// unchanged groups are filtered out so an all-quiet comparison returns "".
// Original copyright belongs to blacktop; see internal/vendored/LICENSE.ipsw.
package vmacho

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types/objc"
)

// objcModel is the structural snapshot of a dylib's ObjC metadata, keyed by
// name so two versions can be compared regardless of on-disk ordering. Values
// are pointers into the parser's result slices (the structs are large and only
// read).
type objcModel struct {
	classes    map[string]*objc.Class
	protocols  map[string]*objc.Protocol
	categories map[string]*objc.Category
}

func newObjcModel(f *macho.File) (*objcModel, error) {
	m := &objcModel{
		classes:    map[string]*objc.Class{},
		protocols:  map[string]*objc.Protocol{},
		categories: map[string]*objc.Category{},
	}
	classes, err := f.GetObjCClasses()
	if err != nil && !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return nil, fmt.Errorf("failed to get ObjC classes: %w", err)
	}
	for i := range classes {
		m.classes[classes[i].Name] = &classes[i]
	}
	protos, err := f.GetObjCProtocols()
	if err != nil && !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return nil, fmt.Errorf("failed to get ObjC protocols: %w", err)
	}
	for i := range protos {
		m.protocols[protos[i].Name] = &protos[i]
	}
	cats, err := f.GetObjCCategories()
	if err != nil && !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return nil, fmt.Errorf("failed to get ObjC categories: %w", err)
	}
	for i := range cats {
		m.categories[cats[i].Name] = &cats[i]
	}
	return m, nil
}

// DiffObjC structurally compares the ObjC metadata of newM against oldM:
// added/removed/changed classes, protocols, and categories, identity keyed by
// name/selector so the result is stable no matter what order the dylibs emit
// their ObjC symbols. Returns "" when nothing changed. Panics from the
// underlying parser are converted to errors.
func DiffObjC(oldM, newM *macho.File) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("objc structural diff panic: %v", r)
		}
	}()
	newModel, err := newObjcModel(newM)
	if err != nil {
		return "", err
	}
	oldModel, err := newObjcModel(oldM)
	if err != nil {
		return "", err
	}

	return joinDiffSections([]string{
		diffClasses(oldModel.classes, newModel.classes),
		diffProtocols(oldModel.protocols, newModel.protocols),
		diffCategories(oldModel.categories, newModel.categories),
	}), nil
}

// methodKeys returns selector keys for instance ("-") and class ("+") methods,
// matching ObjC method notation.
func methodKeys(instance, class []objc.Method) map[string]struct{} {
	keys := make(map[string]struct{}, len(instance)+len(class))
	for _, m := range instance {
		keys["-"+m.Name] = struct{}{}
	}
	for _, m := range class {
		keys["+"+m.Name] = struct{}{}
	}
	return keys
}

func protocolKeys(protos []objc.Protocol) map[string]struct{} {
	keys := make(map[string]struct{}, len(protos))
	for _, p := range protos {
		keys["<"+p.Name+">"] = struct{}{}
	}
	return keys
}

// propertyKeys preserves all encoded attributes, including backing ivars and
// custom accessors that the display declarations omit. Only attribute order is
// ignored; commas within quoted names or composite types remain part of a type.
func propertyKeys(props []objc.Property, kind string) map[string]struct{} {
	keys := make(map[string]struct{}, len(props))
	for _, p := range props {
		var attrs []string
		start, depth := 0, 0
		quoted, escaped := false, false
		for i, ch := range p.EncodedAttributes {
			if escaped {
				escaped = false
				continue
			}
			if quoted && ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = !quoted
			} else if !quoted {
				switch ch {
				case '{', '(', '[':
					depth++
				case '}', ')', ']':
					if depth > 0 {
						depth--
					}
				case ',':
					if depth == 0 {
						attrs = append(attrs, p.EncodedAttributes[start:i])
						start = i + 1
					}
				}
			}
		}
		attrs = append(attrs, p.EncodedAttributes[start:])
		slices.Sort(attrs)
		keys[fmt.Sprintf("@property %s%s [%s]", kind, p.Name, strings.Join(attrs, ","))] = struct{}{}
	}
	return keys
}

func diffClasses(prev, next map[string]*objc.Class) string {
	return diffSection("Classes", prev, next,
		func(c *objc.Class) map[string]struct{} {
			keys := methodKeys(c.InstanceMethods, c.ClassMethods)
			for k := range protocolKeys(c.Protocols) {
				keys[k] = struct{}{}
			}
			for k := range propertyKeys(c.Props, "-") {
				keys[k] = struct{}{}
			}
			return keys
		},
		func(c *objc.Class) string {
			return fmt.Sprintf("%s : %s  (%d methods)", c.Name, c.SuperClass, len(c.InstanceMethods)+len(c.ClassMethods))
		})
}

func diffProtocols(prev, next map[string]*objc.Protocol) string {
	return diffSection("Protocols", prev, next,
		func(p *objc.Protocol) map[string]struct{} {
			keys := methodKeys(p.InstanceMethods, p.ClassMethods)
			for _, m := range p.OptionalInstanceMethods {
				keys["-"+m.Name] = struct{}{}
			}
			for _, m := range p.OptionalClassMethods {
				keys["+"+m.Name] = struct{}{}
			}
			for k := range propertyKeys(p.InstanceProperties, "-") {
				keys[k] = struct{}{}
			}
			for k := range propertyKeys(p.ClassProperties, "+") {
				keys[k] = struct{}{}
			}
			return keys
		},
		func(p *objc.Protocol) string { return p.Name })
}

func diffCategories(prev, next map[string]*objc.Category) string {
	return diffSection("Categories", prev, next,
		func(c *objc.Category) map[string]struct{} {
			keys := methodKeys(c.InstanceMethods, c.ClassMethods)
			for k := range propertyKeys(c.Properties, "-") {
				keys[k] = struct{}{}
			}
			return keys
		},
		func(c *objc.Category) string { return c.Name })
}
