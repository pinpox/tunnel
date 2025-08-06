package main

import (
	"testing"
)

func Test_genPublicWgKey(t *testing.T) {

	tests := []struct {
		name       string
		privateKey string
		want       string
	}{
		{
			name:       "Dervie public key from private",
			privateKey: "4G+L0tzoX/b29KV1hUBaT69+CLyHgExpUXmQDfEl7Ew=",
			want:       "VAmKW5nH5iauM8BjS6QGjUV3id7ji9bqOzoKMdVyanU=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			priv, err := base64ToKey(tt.privateKey)
			if err != nil {
				t.Error(err)
			}

			gotBytes := genPublicWgKey(priv)
			gotString := keyToBase64(gotBytes)

			if gotString != tt.want {
				t.Errorf("genPublicWgKey() = %v, want %v", gotString, tt.want)
			}
		})
	}
}
