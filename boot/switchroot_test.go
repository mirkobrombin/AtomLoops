package boot

import (
	"reflect"
	"testing"
)

func TestCarriedMountsReadsEveryMountBeforeMoving(t *testing.T) {
	mounts := "rootfs / rootfs rw 0 0\n" +
		"proc /proc proc rw 0 0\n" +
		"sysfs /sys sysfs rw 0 0\n" +
		"devtmpfs /dev devtmpfs rw 0 0\n" +
		"tmpfs /run tmpfs rw 0 0\n" +
		"/dev/dm-0 /sysroot erofs ro 0 0\n"
	want := []string{"/dev", "/proc", "/sys", "/run"}
	if got := carriedMounts(mounts); !reflect.DeepEqual(got, want) {
		t.Fatalf("carriedMounts = %v, want %v", got, want)
	}
}

func TestCarriedMountsSkipsAbsentMounts(t *testing.T) {
	mounts := "proc /proc proc rw 0 0\ndevtmpfs /dev devtmpfs rw 0 0\n"
	want := []string{"/dev", "/proc"}
	if got := carriedMounts(mounts); !reflect.DeepEqual(got, want) {
		t.Fatalf("carriedMounts = %v, want %v", got, want)
	}
}

func TestCarriedMountsIgnoresSubmounts(t *testing.T) {
	mounts := "tmpfs /run/esp-surface vfat ro 0 0\nsysfs /sys/kernel/config configfs rw 0 0\n"
	if got := carriedMounts(mounts); len(got) != 0 {
		t.Fatalf("carriedMounts = %v, want none", got)
	}
}
