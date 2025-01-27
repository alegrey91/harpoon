package elfreader

import (
	"testing"
)

func Test_isGoroutine(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "is not goroutine",
			args: args{
				s: "github.com/alegrey91/harpoon/internal/archiver.Convert",
			},
			want: false,
		},
		{
			name: "is goroutine",
			args: args{
				s: "debug/dwarf.(*Data).readType.func1",
			},
			want: true,
		},
		{
			name: "is goroutine",
			args: args{
				s: "debug/dwarf.(*Data).readType.func2",
			},
			want: true,
		},
		{
			name: "is goroutine",
			args: args{
				s: "os.ReadDir.func1",
			},
			want: true,
		},
		{
			name: "is goroutine",
			args: args{
				s: "github.com/myuser/myproject/pkg/api.ForbiddenListSpec.ExactMatch.SearchStrings.func2",
			},
			want: true,
		},
		{
			name: "is goroutine",
			args: args{
				s: "github.com/prometheus/client_golang/prometheus.goRuntimeMemStats.func21",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGoroutine(tt.args.s); got != tt.want {
				t.Errorf("isGoroutine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isTestFunction(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "is test function",
			args: args{
				s: "github.com/myuser/myproject/api/v1beta1.TestOwnerListSpec_FindOwner",
			},
			want: true,
		},
		{
			name: "is not test function",
			args: args{
				s: "net/http.http2got1xxFuncForTests",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTestFunction(tt.args.s); got != tt.want {
				t.Errorf("isTestFunction() = %v, want %v", got, tt.want)
			}
		})
	}
}
