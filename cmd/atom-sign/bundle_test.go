package main

import "testing"

func TestBundleOptIn(t *testing.T) {
	var b bundleList
	if err := b.Set("name=a,img=a.img,url=u,version=1,opt-in=true"); err != nil {
		t.Fatal(err)
	}
	if err := b.Set("name=b,img=b.img,url=u,version=1"); err != nil {
		t.Fatal(err)
	}
	if !b[0].OptIn || b[1].OptIn {
		t.Fatalf("opt-in %v %v", b[0].OptIn, b[1].OptIn)
	}
	if b.Set("name=c,img=c.img,url=u,version=1,opt-in=maybe") == nil {
		t.Fatal("accepted opt-in=maybe")
	}
}
