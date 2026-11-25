//go:build !linux

package main

func watchStateFile(path string, notify func()) {}
