package aws

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestValidator_ValidateAudience(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewValidator(logger, []string{"test-audience"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		token   *AWSTokenData
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid audience",
			token: &AWSTokenData{
				Headers: []Header{
					{Key: "x-goog-cloud-target-resource", Value: "test-audience"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing audience header",
			token: &AWSTokenData{
				Headers: []Header{
					{Key: "other-header", Value: "some-value"},
				},
			},
			wantErr: true,
			errMsg:  "token does not contain required x-goog-cloud-target-resource header",
		},
		{
			name: "wrong audience",
			token: &AWSTokenData{
				Headers: []Header{
					{Key: "x-goog-cloud-target-resource", Value: "wrong-audience"},
				},
			},
			wantErr: true,
			errMsg:  "token audience mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateAudience(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateAudienceMultiple(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewValidator(logger, []string{"audience-1", "audience-2", "audience-3"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		token   *AWSTokenData
		wantErr bool
		errMsg  string
	}{
		{
			name: "matches first audience",
			token: &AWSTokenData{
				Headers: []Header{
					{Key: "x-goog-cloud-target-resource", Value: "audience-1"},
				},
			},
			wantErr: false,
		},
		{
			name: "matches second audience",
			token: &AWSTokenData{
				Headers: []Header{
					{Key: "x-goog-cloud-target-resource", Value: "audience-2"},
				},
			},
			wantErr: false,
		},
		{
			name: "matches third audience",
			token: &AWSTokenData{
				Headers: []Header{
					{Key: "x-goog-cloud-target-resource", Value: "audience-3"},
				},
			},
			wantErr: false,
		},
		{
			name: "no matching audience",
			token: &AWSTokenData{
				Headers: []Header{
					{Key: "x-goog-cloud-target-resource", Value: "wrong-audience"},
				},
			},
			wantErr: true,
			errMsg:  "token audience mismatch: token contains \"wrong-audience\", but expected one of [audience-1 audience-2 audience-3]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateAudience(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateTokenParsing(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewValidator(logger, []string{"test-audience"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid URL encoding",
			token: "invalid%zztoken",
			wantErr: true,
			errMsg:  "failed to URL decode token",
		},
		{
			name: "invalid JSON",
			token: url.QueryEscape("{invalid-json"),
			wantErr: true,
			errMsg:  "failed to parse AWS token JSON",
		},
		{
			name: "valid JSON structure",
			token: func() string {
				tokenData := AWSTokenData{
					URL:    "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
					Method: "POST",
					Headers: []Header{
						{Key: "x-goog-cloud-target-resource", Value: "test-audience"},
						{Key: "authorization", Value: "AWS4-HMAC-SHA256 Credential=..."},
					},
				}
				jsonBytes, _ := json.Marshal(tokenData)
				return url.QueryEscape(string(jsonBytes))
			}(),
			wantErr: true, // Will fail at AWS validation step, but parsing should succeed
			errMsg:  "AWS STS validation failed", // Expected to fail at AWS validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.Validate(context.Background(), tt.token)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewValidator(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name      string
		audiences []string
		wantErr   bool
	}{
		{
			name:      "valid configuration",
			audiences: []string{"test-audience"},
			wantErr:   false,
		},
		{
			name:      "multiple audiences",
			audiences: []string{"audience-1", "audience-2"},
			wantErr:   false,
		},
		{
			name:      "empty audiences",
			audiences: []string{},
			wantErr:   false, // Audience validation happens during token validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewValidator(logger, tt.audiences)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, validator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validator)
				assert.Equal(t, tt.audiences, validator.audiences)
			}
		})
	}
}

func TestValidator_ValidateSTSURL(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewValidator(logger, []string{"test-audience"})
	require.NoError(t, err)

	tests := []struct {
		name     string
		tokenURL string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "global endpoint",
			tokenURL: "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
			wantErr:  false,
		},
		{
			name:     "us-west-2 regional endpoint",
			tokenURL: "https://sts.us-west-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
			wantErr:  false,
		},
		{
			name:     "eu-west-1 regional endpoint",
			tokenURL: "https://sts.eu-west-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
			wantErr:  false,
		},
		{
			name:     "invalid URL",
			tokenURL: "not-a-url",
			wantErr:  true,
			errMsg:   "must use HTTPS",
		},
		{
			name:     "HTTP not HTTPS",
			tokenURL: "http://sts.amazonaws.com/",
			wantErr:  true,
			errMsg:   "must use HTTPS",
		},
		{
			name:     "non-STS hostname",
			tokenURL: "https://ec2.us-east-1.amazonaws.com/",
			wantErr:  true,
			errMsg:   "invalid AWS STS hostname",
		},
		{
			name:     "non-AWS hostname",
			tokenURL: "https://example.com/",
			wantErr:  true,
			errMsg:   "invalid AWS STS hostname",
		},
		{
			name:     "malicious region with dots",
			tokenURL: "https://sts.us-west-2.evil.amazonaws.com/",
			wantErr:  true,
			errMsg:   "invalid AWS region",
		},
		{
			name:     "empty region",
			tokenURL: "https://sts..amazonaws.com/",
			wantErr:  true,
			errMsg:   "invalid AWS region",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateSTSURL(tt.tokenURL)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAWSTokenData_JSONSerialization(t *testing.T) {
	tokenData := AWSTokenData{
		URL:    "https://sts.us-east-1.amazonaws.com/",
		Method: "POST",
		Headers: []Header{
			{Key: "host", Value: "sts.us-east-1.amazonaws.com"},
			{Key: "x-goog-cloud-target-resource", Value: "test-audience"},
		},
	}

	// Test marshaling
	jsonBytes, err := json.Marshal(tokenData)
	require.NoError(t, err)

	// Test unmarshaling
	var unmarshaled AWSTokenData
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, tokenData.URL, unmarshaled.URL)
	assert.Equal(t, tokenData.Method, unmarshaled.Method)
	assert.Equal(t, len(tokenData.Headers), len(unmarshaled.Headers))
	
	for i, header := range tokenData.Headers {
		assert.Equal(t, header.Key, unmarshaled.Headers[i].Key)
		assert.Equal(t, header.Value, unmarshaled.Headers[i].Value)
	}
}