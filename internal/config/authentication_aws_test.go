package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.flipt.io/flipt/rpc/flipt/auth"
)

func TestAuthenticationMethodAWSConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  AuthenticationMethodAWSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration",
			config: AuthenticationMethodAWSConfig{
				Audiences: []string{"test-audience"},
			},
			wantErr: false,
		},
		{
			name: "multiple audiences",
			config: AuthenticationMethodAWSConfig{
				Audiences: []string{"audience-1", "audience-2"},
			},
			wantErr: false,
		},
		{
			name: "missing required audiences",
			config: AuthenticationMethodAWSConfig{},
			wantErr: true,
			errMsg:  "audiences non-empty value is required",
		},
		{
			name: "empty audiences slice",
			config: AuthenticationMethodAWSConfig{
				Audiences: []string{},
			},
			wantErr: true,
			errMsg:  "audiences non-empty value is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthenticationMethodAWSConfig_SetDefaults(t *testing.T) {
	config := AuthenticationMethodAWSConfig{}
	defaults := make(map[string]any)
	
	config.setDefaults(defaults)
	
	// AWS method has no defaults
	assert.Empty(t, defaults)
}

func TestAuthenticationMethodAWSConfig_Info(t *testing.T) {
	config := AuthenticationMethodAWSConfig{
		Audiences: []string{"test-audience"},
	}
	
	info := config.info(nil)
	
	assert.Equal(t, auth.Method_METHOD_AWS, info.Method)
	assert.False(t, info.SessionCompatible)
	assert.Nil(t, info.Metadata) // AWS method doesn't expose metadata in info
}

func TestAuthenticationMethodsConfig_AllMethods_IncludesAWS(t *testing.T) {
	config := &AuthenticationMethodsConfig{
		AWS: AuthenticationMethod[AuthenticationMethodAWSConfig]{
			Enabled: true,
			Method: AuthenticationMethodAWSConfig{
				Audiences: []string{"test-audience"},
			},
		},
	}
	
	methods := config.AllMethods(context.Background())
	
	// Should include AWS method
	var awsMethod *StaticAuthenticationMethodInfo
	for _, method := range methods {
		if method.Method == auth.Method_METHOD_AWS {
			awsMethod = &method
			break
		}
	}
	
	require.NotNil(t, awsMethod, "AWS method should be included in AllMethods()")
	assert.True(t, awsMethod.Enabled)
	assert.Equal(t, auth.Method_METHOD_AWS, awsMethod.Method)
	assert.False(t, awsMethod.SessionCompatible)
}

func TestAuthenticationConfig_EnabledMethods_AWS(t *testing.T) {
	config := &AuthenticationMethodsConfig{
		AWS: AuthenticationMethod[AuthenticationMethodAWSConfig]{
			Enabled: true,
			Method: AuthenticationMethodAWSConfig{
				Audiences: []string{"test-audience"},
			},
		},
		Token: AuthenticationMethod[AuthenticationMethodTokenConfig]{
			Enabled: false, // Disabled for comparison
		},
	}
	
	enabledMethods := config.EnabledMethods()
	
	// Should only include AWS method since token is disabled
	require.Len(t, enabledMethods, 1)
	assert.Equal(t, auth.Method_METHOD_AWS, enabledMethods[0].Method)
	assert.True(t, enabledMethods[0].Enabled)
}