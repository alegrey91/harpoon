package archiver

import "testing"

func TestConvert(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test_1",
			args: args{
				name: "internal/abi.(*Type).ExportedMethods",
			},
			want: "internal_abi_(*Type)_ExportedMethods",
		},
		{
			name: "test_2",
			args: args{
				name: "github.com/alegrey91/test/pkg/randomic.PrintString",
			},
			want: "github_com_alegrey91_test_pkg_randomic_PrintString",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Convert(tt.args.name); got != tt.want {
				t.Errorf("Convert() = %v, want %v", got, tt.want)
			}
		})
	}
}
