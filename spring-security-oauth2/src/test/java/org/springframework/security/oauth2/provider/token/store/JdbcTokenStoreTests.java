package org.springframework.security.oauth2.provider.token.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;

import java.util.List;
import org.company.oauth2.CustomOAuth2AccessToken;
import org.company.oauth2.CustomOAuth2Authentication;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.SerializationStrategy;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.common.util.WhitelistedSerializationStrategy;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

/**
 * @author Dave Syer
 * @author Artem Smotrakov
 */
public class JdbcTokenStoreTests extends TokenStoreBaseTests {

	private JdbcTokenStore tokenStore;

	private EmbeddedDatabase db;

	@Override
	public JdbcTokenStore getTokenStore() {
		return tokenStore;
	}
	
	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		tokenStore = new JdbcTokenStore(db);
	}

	@Test
	public void testFindAccessTokensByUserName() {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByUserName("test2");
		assertEquals(1, actualOAuth2AccessTokens.size());
	}

	@Test
	public void testNotAllowedToken() {
		OAuth2Authentication expectedAuthentication = new CustomOAuth2Authentication(
				RequestTokenFactory.createOAuth2Request("id", false),
				new TestAuthentication("test2", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new CustomOAuth2AccessToken("customToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByUserName("test2");
		assertTrue(actualOAuth2AccessTokens.isEmpty());
	}

	@Test
	public void testAllowedToken() {
		OAuth2Authentication expectedAuthentication = new CustomOAuth2Authentication(
				RequestTokenFactory.createOAuth2Request("id", false),
				new TestAuthentication("test3", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new CustomOAuth2AccessToken("customToken");
		JdbcTokenStore tokenStore = getTokenStore();
		List<String> allowedClasses = new ArrayList<String>();
		allowedClasses.add("java.util.");
		allowedClasses.add("org.springframework.security.");
		allowedClasses.add("org.company.oauth2.CustomOAuth2AccessToken");
		allowedClasses.add("org.company.oauth2.CustomOAuth2Authentication");
		WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy(allowedClasses);
		SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
		try {
			SerializationUtils.setSerializationStrategy(newStrategy);
			tokenStore.storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

			Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByUserName("test3");
			assertEquals(1, actualOAuth2AccessTokens.size());

			OAuth2AccessToken actualToken = actualOAuth2AccessTokens.iterator().next();
			assertEquals(expectedOAuth2AccessToken, actualToken);
		} finally {
			SerializationUtils.setSerializationStrategy(oldStrategy);
		}
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

}
