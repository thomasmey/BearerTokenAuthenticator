package de.m3y3r.catalina.startup;

import java.util.HashMap;
import java.util.Map;

import org.apache.catalina.Authenticator;
import org.apache.catalina.startup.ContextConfig;

import de.m3y3r.catalina.authenticator.BearerTokenAuthenticator;

public class CustomContextConfig extends ContextConfig {

	public CustomContextConfig() {
		super();
		Map<String, Authenticator> customAuthenticators = new HashMap<>();
		customAuthenticators.put("BEARER", new BearerTokenAuthenticator());
		this.setCustomAuthenticators(customAuthenticators);
	}
}
