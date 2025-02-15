package syscallutils

import (
	"reflect"
	"testing"
)

func TestGetVariants(t *testing.T) {
	type args struct {
		syscall string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "no variants",
			args: args{
				syscall: "open",
			},
			want: nil,
		},
		{
			name: "no variants due to empty syscall",
			args: args{
				syscall: "",
			},
			want: nil,
		},
		{
			name: "dup variants",
			args: args{
				syscall: "dup",
			},
			want: []string{"dup", "dup2", "dup3"},
		},
		{
			name: "inotify_init variants (start from last variant)",
			args: args{
				syscall: "inotify_init1",
			},
			want: []string{"inotify_init", "inotify_init1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetVariants(tt.args.syscall); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetVariants() = %v, want %v", got, tt.want)
			}
		})
	}
}
