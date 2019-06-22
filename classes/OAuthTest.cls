/**
* The OAuthTest class implements test cases for OAuth class.
* All data used in this test belongs to TwitterApi manual for
* OAuth signature generation.
* https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature.html
* @author  		Daniel Palacios Hidalgo
* @version 		1.0
* @since    	2019-06-23 
* @targetClass 	OAuth
*/
@isTest
public class OAuthTest {
	/**
     * Test case to obtain Url without params 
     * in an URL with params.
     * @result the url will be trimmed to exclude GET params.
     */
    @isTest
    public static void getBaseUrlWithUrlParamsCase() {
        OAuth oAuth = new OAuth('', '', '', '');
        String urlString = 'https://www.example.com/users?id=8';
        String expectedUrl = 'https://www.example.com/users';
        
        Url url = new Url(urlString);
        
        Test.startTest();
        System.assertEquals(expectedUrl, oAuth.getBaseUrl(url));
        Test.stopTest();
    }
    
    /**
     * Test case to obtain Url without params 
     * in an URL without params.
     * @result the url will remain the same.
     */
    @isTest
    public static void getBaseUrlWithoutUrlParamsCase() {
        OAuth oAuth = new OAuth('', '', '', '');
        String urlString = 'https://www.example.com/users';
        String expectedUrl = 'https://www.example.com/users';
        
        Url url = new Url(urlString);
        
        Test.startTest();
        System.assertEquals(expectedUrl, oAuth.getBaseUrl(url));
        Test.stopTest();
    }
    
    /**
     * Test case to obtain a correct 
     * hash-based message authentication code.
     * @result a correct hash signature.
     */
    @isTest
    public static void getSignatureCase() {
        OAuth oAuth = new OAuth('', '', '', '');
        String input = 'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521';
        String signingKey = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
        String expectedSignature = 'hCtSmYh+iHYCEqBWrE7C7hYmtUk=';
        
        Test.startTest();
        System.assertEquals(expectedSignature, oAuth.HMACSHA1(input, signingKey));
        Test.stopTest();
    }
    
    /**
     * Test case to obtain a correct 
     * signing key from consumer secret and 
     * secret access token.
     * @result a correct signing key.
     */
    @isTest
    public static void generateSigningKeyCase() {
        String consumerKey = 'xvz1evFS4wEEPTGEFPHBog';
        String consumerSecret = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw';
        String oAuthToken = '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb';
        String accessTokenSecret = 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
        String expectedSigningKey = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
        
        OAuth oauth = new OAuth(consumerKey, consumerSecret, oAuthToken, accessTokenSecret);
        
        Test.startTest();
        System.assertEquals(expectedSigningKey, oauth.generateSigningKey());
        Test.stopTest();
    }
    
    /**
     * Test case to check correct 
     * base string generation from http method, 
     * url and the string parameters.
     * @result a base signature string.
     */
    @isTest
    public static void getBaseStringCase() {
        String httpMethod = 'POST';
        String url = 'https://api.twitter.com/1.1/statuses/update.json';
        String paramString = 'include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21';
        String expectedBaseString = 'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521';
        
        Test.startTest();
        System.assertEquals(expectedBaseString, OAuth.getBaseString(httpMethod, url, paramString));
        Test.stopTest();
    }
    
    /**
     * Test case to check for correct sorting of
     * OAuth parameters. Those parameters should be
     * ordered alphabetically. 
     * @result List of ordered oAuth params.
     */
    @isTest
    public static void oAuthParamSortTest() {
        List<OAuth.OAuthParam> orderedOAuthParamList = new List<OAuth.OAuthParam>();
        List<OAuth.OAuthParam> unorderedOAuthParamList = new List<OAuth.OAuthParam>();
        
        // Ordered oAuth param list.
        orderedOAuthParamList.add(new OAuth.OAuthParam('include_entities', 'true', false));
        orderedOAuthParamList.add(new OAuth.OAuthParam('oauth_consumer_key', 'xvz1evFS4wEEPTGEFPHBog', true));
        orderedOAuthParamList.add(new OAuth.OAuthParam('oauth_nonce', 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg', true));
        orderedOAuthParamList.add(new OAuth.OAuthParam('oauth_signature_method', 'HMAC-SHA1', true));
        orderedOAuthParamList.add(new OAuth.OAuthParam('oauth_timestamp', '1318622958', true));
        orderedOAuthParamList.add(new OAuth.OAuthParam('oauth_token', '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb', true));
        orderedOAuthParamList.add(new OAuth.OAuthParam('oauth_version', '1.0', true));
        
        // Random ordered list of oAuth params.
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_token', '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb', true));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_version', '1.0', true));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('include_entities', 'true', false));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_nonce', 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg', true));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_signature_method', 'HMAC-SHA1', true));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_consumer_key', 'xvz1evFS4wEEPTGEFPHBog', true));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_timestamp', '1318622958', true));
        
        
        Test.startTest();
        unorderedOAuthParamList.sort();
        
        // Check for same size.
        System.assertEquals(orderedOAuthParamList.size(), unorderedOAuthParamList.size());
        
        // Check for all parameters to be the same and ordered alphabetically.
        for(Integer i = 0; i < unorderedOAuthParamList.size(); i++) {
        	System.assertEquals(orderedOAuthParamList[i].getKey(), unorderedOAuthParamList[i].getKey());
            System.assertEquals(orderedOAuthParamList[i].getValue(), unorderedOAuthParamList[i].getValue());
            System.assertEquals(orderedOAuthParamList[i].getEncodedKey(), unorderedOAuthParamList[i].getEncodedKey());
            System.assertEquals(orderedOAuthParamList[i].getEncodedValue(), unorderedOAuthParamList[i].getEncodedValue());
            System.assertEquals(orderedOAuthParamList[i].getIsOAuthData(), unorderedOAuthParamList[i].getIsOAuthData());            
        }
        Test.stopTest();
    }
    
    
    /**
     * Test case to check for correct param string
     * according to oAuth parameters order when a list 
     * is ordered.
     * @result String used for oAuth signature.
     */
    @isTest
    public static void getParamStringOrderedCase() {
        List<OAuth.OAuthParam> OAuthParamList = new List<OAuth.OAuthParam>();
        String expectedParamString = 'include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0';
        
        OAuthParamList.add(new OAuth.OAuthParam('include_entities', 'true', false));
        OAuthParamList.add(new OAuth.OAuthParam('oauth_consumer_key', 'xvz1evFS4wEEPTGEFPHBog', false));
        OAuthParamList.add(new OAuth.OAuthParam('oauth_nonce', 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg', false));
        OAuthParamList.add(new OAuth.OAuthParam('oauth_signature_method', 'HMAC-SHA1', false));
        OAuthParamList.add(new OAuth.OAuthParam('oauth_timestamp', '1318622958', false));
        OAuthParamList.add(new OAuth.OAuthParam('oauth_token', '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb', false));
        OAuthParamList.add(new OAuth.OAuthParam('oauth_version', '1.0', false));
        
        Test.startTest();
        // Sort before generation.
        OAuthParamList.sort();
        // Assert correct string generation.
        System.assertEquals(expectedParamString, OAuth.getParamString(OAuthParamList));
        Test.stopTest();
    }
    
    /**
     * Test case to check for correct param string
     * according to oAuth parameters order when a list 
     * is unordered.
     * @result String used for oAuth signature.
     */
    @isTest
    public static void getParamStringUnorderedStringCase() {
        List<OAuth.OAuthParam> unorderedOAuthParamList = new List<OAuth.OAuthParam>();
        String expectedParamString = 'include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0';
        
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_token', '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb', false));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_version', '1.0', false));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('include_entities', 'true', false));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_nonce', 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg', false));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_signature_method', 'HMAC-SHA1', false));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_consumer_key', 'xvz1evFS4wEEPTGEFPHBog', false));
        unorderedOAuthParamList.add(new OAuth.OAuthParam('oauth_timestamp', '1318622958', false));
        
        Test.startTest(); 
        // oAuthList is not ordered, method is expected to order it correctly.
        System.assertEquals(expectedParamString, OAuth.getParamString(unorderedOAuthParamList));
        Test.stopTest();
    } 
    
    /**
     * Test case to check for correct oAuth params 
     * extraction from all oAuth data.
     * @result ordered oAuthParam list.
     */
    @isTest
    public static void getParamListCase() {
        String consumerKey = 'xvz1evFS4wEEPTGEFPHBog';
        String consumerSecret = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw';
        String oAuthToken = '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb';
        String accessTokenSecret = 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
        String timestamp = '1318622958';
        String nonce = 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg';
        String urlString = 'https://api.twitter.com/1.1/statuses/update.json/1.1/statuses/update.json?include_entities=true';
        OAuth oauth = new OAuth(consumerKey, consumerSecret, oAuthToken, accessTokenSecret);
		Url url = new Url(urlString);
        List<OAuth.OAuthParam> expectedParamList = new List<OAuth.OAuthParam>();
        List<OAuth.OAuthParam> actualParamList;
        
        expectedParamList.add(new OAuth.OAuthParam('include_entities', 'true', false));
        expectedParamList.add(new OAuth.OAuthParam('oauth_consumer_key', 'xvz1evFS4wEEPTGEFPHBog', true));
        expectedParamList.add(new OAuth.OAuthParam('oauth_nonce', 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg', true));
        expectedParamList.add(new OAuth.OAuthParam('oauth_signature_method', 'HMAC-SHA1', true));
        expectedParamList.add(new OAuth.OAuthParam('oauth_timestamp', '1318622958', true));
        expectedParamList.add(new OAuth.OAuthParam('oauth_token', '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb', true));
        expectedParamList.add(new OAuth.OAuthParam('oauth_version', '1.0', true));
        
        expectedParamList.sort();
        
        Test.startTest();
        actualParamList = oAuth.getOAuthParamList(url, nonce, timestamp);
        
        // Check for correct quantity of params extracted.
        System.assertEquals(expectedParamList.size(), actualParamList.size());
        
        // Check for correct value settings.
        for(Integer i = 0; i < actualParamList.size(); i++) {
            System.assertEquals(expectedParamList[i].getKey(), actualParamList[i].getKey());
            System.assertEquals(expectedParamList[i].getValue(), actualParamList[i].getValue());
            System.assertEquals(expectedParamList[i].getEncodedKey(), actualParamList[i].getEncodedKey());
            System.assertEquals(expectedParamList[i].getEncodedValue(), actualParamList[i].getEncodedValue());
            System.assertEquals(expectedParamList[i].getIsOAuthData(), actualParamList[i].getIsOAuthData());            
        }
        Test.stopTest();
    }
    
    /**
     * Test case to check for full signature.
     * @result request with authorization header param.
     */
    @isTest
    public static void signCase() {
        String consumerKey = 'xvz1evFS4wEEPTGEFPHBog';
        String consumerSecret = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw';
        String oAuthToken = '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb';
        String accessTokenSecret = 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
        String endpoint = 'https://api.twitter.com/1.1/statuses/update.json/1.1/statuses/update.json?include_entities=true';
        String httpMethod = 'POST';
        String expectedAuthorizationHeader = 'OAuth oauth_consumer_key= "xvz1evFS4wEEPTGEFPHBog", oauth_nonce= "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_signature_method= "HMAC-SHA1", oauth_timestamp= "1318622958", oauth_token= "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", oauth_version= "1.0", oauth_signature="U9M5d11ddkwvOQzhSqmcxdYii04="';
        OAuth oAuth = new OAuth(consumerKey, consumerSecret, oAuthToken, accessTokenSecret);
        
        HttpRequest req = new HttpRequest();
        req.setEndpoint(endpoint);
        req.setMethod(httpMethod);
        
        Test.startTest();
       	req = oAuth.sign(req);
        // Check for correct header param setting.
        System.assertEquals(expectedAuthorizationHeader, req.getHeader('Authorization'));
        Test.stopTest();
    }
    
}