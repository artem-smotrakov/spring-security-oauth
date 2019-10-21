package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.List;
import org.company.oauth2.CustomOAuth2Authentication;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.common.util.SerializationStrategy;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.common.util.WhitelistedSerializationStrategy;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

public class JdbcAuthorizationCodeServicesTests extends AuthorizationCodeServicesBaseTests {
	private JdbcAuthorizationCodeServices authorizationCodeServices;

	private EmbeddedDatabase db;

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		authorizationCodeServices = new JdbcAuthorizationCodeServices(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

	@Override
	AuthorizationCodeServices getAuthorizationCodeServices() {
		return authorizationCodeServices;
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNotAllowed() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new CustomOAuth2Authentication(storedOAuth2Request,
				new TestAuthentication("test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		getAuthorizationCodeServices().consumeAuthorizationCode(code);
	}

	@Test
	public void testCustomImplementation() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new CustomOAuth2Authentication(storedOAuth2Request,
				new TestAuthentication("test3", false));

		AuthorizationCodeServices jdbcAuthorizationCodeServices = getAuthorizationCodeServices();
		List<String> allowedClasses = new ArrayList<String>();
		allowedClasses.add("java.util.");
		allowedClasses.add("org.springframework.security.");
		allowedClasses.add("org.company.oauth2.CustomOAuth2AccessToken");
		allowedClasses.add("org.company.oauth2.CustomOAuth2Authentication");
		WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy(allowedClasses);
		SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
		try {
			SerializationUtils.setSerializationStrategy(newStrategy);
			String code = jdbcAuthorizationCodeServices.createAuthorizationCode(expectedAuthentication);
			assertNotNull(code);

			OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
			assertEquals(expectedAuthentication, actualAuthentication);
		} finally {
			SerializationUtils.setSerializationStrategy(oldStrategy);
		}
	}
}
