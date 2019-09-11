package main

import (
	"context"
	"errors"
	"os"
	"strings"

	firebase "firebase.google.com/go"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"google.golang.org/api/option"
)

func handler(request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	authToken := request.AuthorizationToken
	idToken := strings.Split(authToken, " ")[1]

	ctx := context.Background()

	firebaseConfigString, _ := os.LookupEnv("FIREBASE_CONFIG")
	firebaseConfig := []byte(firebaseConfigString)

	opt := option.WithCredentialsJSON(firebaseConfig)

	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Internal Error")
	}

	client, err := app.Auth(ctx)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Internal Error")
	}

	token, err := client.VerifyIDToken(ctx, idToken)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	context := map[string]interface{}{
		"HH-UID": token.UID,
	}
	return generatePolicy("user", "Allow", request.MethodArn, context), nil
}

func main() {
	lambda.Start(handler)
}

func generatePolicy(principalID, effect string, resource string, context map[string]interface{}) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	authResponse.Context = context
	return authResponse
}
