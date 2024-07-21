package com.taqeem.auth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;

public class GovernmentIDAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String governmentId = context.getHttpRequest().getDecodedFormParameters().getFirst("government_id");
        String password = context.getHttpRequest().getDecodedFormParameters().getFirst("password");

        //Just a checking for the government ID
        if (governmentId == null || password == null) {
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }
        UserModel user = context.getUser();

        if (user == null) {
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }

        boolean valid = context.getAuthenticationSession().getAuthenticatedUser().credentialManager().isValid(UserCredentialModel.password(password));
        if (!valid) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        context.setUser(user);
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No action required
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        // No action required
    }

    @Override
    public void close() {
        // No action required
    }

}
