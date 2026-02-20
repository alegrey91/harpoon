/*
Copyright © 2024 Alessio Greggi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package seccomputils

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// Profile represents a seccomp profile containing a list of allowed syscalls.
type Profile struct {
	Syscalls []string `json:"syscalls"`
}

// LoadProfile reads and parses a seccomp profile from the given file path.
// The profile is expected to be a JSON file with a "syscalls" field containing
// a list of syscall names to be allowed.
func LoadProfile(profilePath string) (*Profile, error) {
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading seccomp profile %s: %w", profilePath, err)
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("error parsing seccomp profile %s: %w", profilePath, err)
	}

	if len(profile.Syscalls) == 0 {
		return nil, fmt.Errorf("seccomp profile %s contains no syscalls", profilePath)
	}

	return &profile, nil
}

// ApplyFilter creates and loads a seccomp whitelist filter based on the
// syscalls listed in the given profile. All syscalls not in the list will
// be denied with EPERM.
func ApplyFilter(profile *Profile) error {
	// Create a "deny all" filter as the default action.
	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return fmt.Errorf("error creating seccomp filter: %w", err)
	}

	// Whitelist each syscall from the profile.
	for _, name := range profile.Syscalls {
		syscallID, err := libseccomp.GetSyscallFromName(name)
		if err != nil {
			return fmt.Errorf("error resolving syscall name %q: %w", name, err)
		}
		if err := filter.AddRule(syscallID, libseccomp.ActAllow); err != nil {
			return fmt.Errorf("error adding rule for syscall %q: %w", name, err)
		}
	}

	// Load (apply) the filter to the current process.
	if err := filter.Load(); err != nil {
		return fmt.Errorf("error loading seccomp filter: %w", err)
	}

	return nil
}
