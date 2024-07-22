package com.taqeem.authenticator;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;


@AutoService(AuthenticatorFactory.class)
public class SmsAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "sms-authenticator";

	private static final SmsAuthenticator SINGLETON = new SmsAuthenticator();

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "SMS Authentication";
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via SMS to the users mobile phone.";
	}

	@Override
	public String getReferenceCategory() {
		return "otp";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		List<ProviderConfigProperty> configProperties=new ArrayList<>();
		configProperties.add(new ProviderConfigProperty(SmsConstants.CODE_LENGTH, "Code length", "The number of digits of the generated code.",
			ProviderConfigProperty.STRING_TYPE, 6));
		configProperties.add(new ProviderConfigProperty(SmsConstants.CODE_TTL, "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"));
		configProperties.add(new ProviderConfigProperty(SmsConstants.SENDER_ID, "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Keycloak"));
		configProperties.add(new ProviderConfigProperty(SmsConstants.SIMULATION_MODE, "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true));
		return configProperties;
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

}
