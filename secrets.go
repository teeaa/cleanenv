package cleanenv

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awssecretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// loadGCPSecret fetches a secret from GCP Secret Manager.
func loadGCPSecret(ctx context.Context, secretVersionName string) (string, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create GCP secret manager client: %w", err)
	}
	defer client.Close()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretVersionName,
	}

	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access GCP secret version %s: %w", secretVersionName, err)
	}

	return string(result.Payload.Data), nil
}

// loadAWSSecret fetches a secret from AWS Secrets Manager.
func loadAWSSecret(ctx context.Context, secretName string) (string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS SDK config: %w", err)
	}

	client := awssecretsmanager.NewFromConfig(cfg)

	input := &awssecretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	}

	result, err := client.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve AWS secret %s: %w", secretName, err)
	}

	if result.SecretString != nil {
		return *result.SecretString, nil
	}

	// If SecretBinary is used, it would need decoding.
	// For this example, we assume SecretString.
	// if result.SecretBinary != nil {
	//  return string(result.SecretBinary), nil
	// }

	return "", fmt.Errorf("AWS secret %s value is empty or not a string", secretName)
}

// LoadConfigFromSecrets populates the fields of a struct pointer with values
// from GCP Secret Manager or AWS Secrets Manager based on struct tags.
// The `configStructPtr` must be a pointer to a struct.
// Fields tagged with `gcp_secret` or `aws_secret` must be of type string.
func LoadConfigFromSecrets(ctx context.Context, configStructPtr interface{}) error {
	val := reflect.ValueOf(configStructPtr)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return fmt.Errorf("input must be a non-nil pointer to a struct")
	}

	elem := val.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("input must be a pointer to a struct")
	}

	typ := elem.Type()

	for i := 0; i < elem.NumField(); i++ {
		field := typ.Field(i)
		fieldVal := elem.Field(i)

		if !fieldVal.CanSet() {
			// This typically means the field is unexported.
			// You might want to log this or skip silently.
			continue
		}

		// Check for GCP secret tag
		if gcpSecretPath, ok := field.Tag.Lookup(TagGcpSecret); ok && gcpSecretPath != "" {
			if field.Type.Kind() != reflect.String {
				return fmt.Errorf("field %s with tag '%s' must be of type string, got %s", field.Name, TagGcpSecret, field.Type.Kind())
			}
			secretValue, err := loadGCPSecret(ctx, gcpSecretPath)
			if err != nil {
				return fmt.Errorf("failed to load GCP secret for field %s (path: %s): %w", field.Name, gcpSecretPath, err)
			}
			fieldVal.SetString(secretValue)
			continue // Processed this field, move to the next
		}

		// Check for AWS secret tag
		if awsSecretName, ok := field.Tag.Lookup(TagAwsSecret); ok && awsSecretName != "" {
			if field.Type.Kind() != reflect.String {
				return fmt.Errorf("field %s with tag '%s' must be of type string, got %s", field.Name, TagAwsSecret, field.Type.Kind())
			}
			secretValue, err := loadAWSSecret(ctx, awsSecretName)
			if err != nil {
				return fmt.Errorf("failed to load AWS secret for field %s (name: %s): %w", field.Name, awsSecretName, err)
			}
			fieldVal.SetString(secretValue)
			continue // Processed this field, move to the next
		}
	}
	return nil
}

// AppConfig is an example configuration struct.
// Replace tag values with your actual secret paths/names.
type AppConfig struct {
	APIKeyGCP     string `gcp_secret:"projects/your-gcp-project-id/secrets/your-api-key-secret/versions/latest"`
	DBPasswordAWS string `aws_secret:"your/db/password_secret_name_or_arn"`
	APITokenAWS   string `aws_secret:"another/aws/secret"`
	RegularValue  string // This field will not be populated from secrets
	UnusedSecret  string `gcp_secret:""` // Empty tag, will be ignored
}

func main() {
	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	config := &AppConfig{
		RegularValue: "Default Local Value",
	}

	fmt.Println("Loading configuration from secrets...")
	err := LoadConfigFromSecrets(ctx, config)
	if err != nil {
		log.Fatalf("Error loading config from secrets: %v", err)
	}

	fmt.Println("Successfully loaded configuration:")
	fmt.Printf("  API Key (GCP): %s\n", config.APIKeyGCP)
	fmt.Printf("  DB Password (AWS): %s\n", config.DBPasswordAWS)
	fmt.Printf("  API Token (AWS): %s\n", config.APITokenAWS)
	fmt.Printf("  Regular Value: %s\n", config.RegularValue)
	fmt.Printf("  Unused Secret Field: '%s'\n", config.UnusedSecret) // Should be empty if tag was empty

	// Important: For this example to run successfully:
	// 1. Ensure GCP and AWS SDKs can authenticate (see prerequisites above).
	// 2. Replace placeholder secret paths/names in `AppConfig` struct tags with actual, accessible secrets.
	//    - For GCP: 'projects/your-gcp-project-id/secrets/your-api-key-secret/versions/latest'
	//    - For AWS: 'your/db/password_secret_name_or_arn' and 'another/aws/secret'
	// 3. The identity running this code must have permissions to access these secrets.
}
