package vmacho

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types/objc"
)

func TestDiffObjC_ClassSuperclassAndIvarChanges(t *testing.T) {
	oldModel := &objcModel{classes: map[string]*objc.Class{
		"Widget": {Name: "Widget", SuperClass: "UIView"},
	}}
	newModel := &objcModel{classes: map[string]*objc.Class{
		"Widget": {Name: "Widget", SuperClass: "UIScrollView"},
	}}

	out := diffObjCModels(oldModel, newModel)
	if !strings.Contains(out, "@@ Classes: +0 added, -0 removed, ~1 changed @@") {
		t.Fatalf("superclass change must mark the class changed:\n%s", out)
	}
	if !strings.Contains(out, "+   extends UIScrollView") || !strings.Contains(out, "-   extends UIView") {
		t.Fatalf("superclass delta missing:\n%s", out)
	}
}

func TestDiffObjC_MethodEncodingChange(t *testing.T) {
	oldModel := &objcModel{classes: map[string]*objc.Class{
		"Widget": {Name: "Widget", InstanceMethods: []objc.Method{{Name: "draw", Types: "v16@0:8"}}},
	}}
	newModel := &objcModel{classes: map[string]*objc.Class{
		"Widget": {Name: "Widget", InstanceMethods: []objc.Method{{Name: "draw", Types: "v20@0:8"}}},
	}}

	out := diffObjCModels(oldModel, newModel)
	if !strings.Contains(out, "~1 changed") {
		t.Fatalf("encoding change must mark the class changed:\n%s", out)
	}
	if !strings.Contains(out, "-   -draw v16@0:8") || !strings.Contains(out, "+   -draw v20@0:8") {
		t.Fatalf("encoding delta missing:\n%s", out)
	}
}

func TestDiffObjC_CategoriesKeyedByOwner(t *testing.T) {
	oldModel := &objcModel{categories: map[string]*objc.Category{
		"Alpha(Extend)": {Name: "Extend", Class: &objc.Class{Name: "Alpha"}},
	}}
	newModel := &objcModel{categories: map[string]*objc.Category{
		"Alpha(Extend)": {Name: "Extend", Class: &objc.Class{Name: "Alpha"}},
		"Beta(Extend)":  {Name: "Extend", Class: &objc.Class{Name: "Beta"}},
	}}

	out := diffObjCModels(oldModel, newModel)
	if !strings.Contains(out, "+ Beta(Extend)") {
		t.Fatalf("new owner-qualified category missing:\n%s", out)
	}
	if strings.Contains(out, "+ Alpha(Extend)") {
		t.Fatalf("unchanged category must not be reported added:\n%s", out)
	}
}
