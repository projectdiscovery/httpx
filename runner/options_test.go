
func TestValidateOptions_Protocol(t *testing.T) {
	tests := []struct {
		protocol string
		wantErr  bool
	}{
		{"", false},
		{"unknown", false},
		{"UNKNOWN", false},
		{"http11", false},
		{"HTTP11", false},
		{"http2", false},
		{"HTTP2", false},
		{"http3", false},
		{"HTTP3", false},
		{"http10", true},
		{"invalid", true},
	}

	for _, tc := range tests {
		t.Run(tc.protocol, func(t *testing.T) {
			opts := &Options{
				Protocol: tc.protocol,
			}
			err := opts.ValidateOptions()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
