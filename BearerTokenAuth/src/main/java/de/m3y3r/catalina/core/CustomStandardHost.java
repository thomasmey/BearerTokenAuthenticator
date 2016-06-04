package de.m3y3r.catalina.core;

import org.apache.catalina.core.StandardHost;

public class CustomStandardHost extends StandardHost {

	public CustomStandardHost() {
		super();
		this.setConfigClass("de.m3y3r.catalina.authenticator.BearerTokenAuthenticator");
	}
}
