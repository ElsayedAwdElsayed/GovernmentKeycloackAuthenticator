package com.taqeem.auth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class GovernmentIdAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "government-id-authenticator";

    @Override
    public String getDisplayType() {
        return "Government ID Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "government-id";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new GovernmentIDAuthenticator();
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // Initialization configuration if needed
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
        // Post initialization configuration if needed
    }

    @Override
    public void close() {
        // Close resources if needed
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("government-id")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Government ID")
                .helpText("Custom attribute for Government ID authentication")
                .add()
                .build();
    }

    @Override
    public String getHelpText() {
        return "Authenticator that validates user based on Government ID.";
    }

}
