package com.lseg.dataplatform.example;

import kong.unirest.*;
import kong.unirest.json.JSONObject;

import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;

import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import software.amazon.awssdk.services.sqs.model.Message;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.net.URI;



public class Alerts 
{
    public static void main( String[] args )
    {
    	
        String username = "<username>";
        String password = "<password>";
        String clientId = "<client id>";
        System.out.println("News Headlines Subscription ...");
        Alerts app = new Alerts();
        
        System.out.println("1. Login ...");
        String token = app.GetToken(username,password, clientId);
        System.out.println("Token: "+token);
        
        System.out.println("\n2. Subscribe news headlines ...");
        
        JsonNode newsResponse = app.SubscribeNewsHeadlines(token);
        
        System.out.println("Endpoint: "+newsResponse.getObject().getJSONObject("transportInfo").getString("endpoint"));
        String endPoint = newsResponse.getObject().getJSONObject("transportInfo").getString("endpoint");
        String cryptographyKey = newsResponse.getObject().getJSONObject("transportInfo").getString("cryptographyKey");
        String subscriptionID = newsResponse.getObject().getString("subscriptionID");
        System.out.println("\n3. Get cloud credentials ..."); 
        JsonNode cloudCredResponse = app.GetCloudCredential(token , endPoint);
        System.out.println(cloudCredResponse.toString());
        String accessKeyId = cloudCredResponse.getObject().getJSONObject("credentials").getString("accessKeyId");
        String secretKey = cloudCredResponse.getObject().getJSONObject("credentials").getString("secretKey");
        String sessionToken = cloudCredResponse.getObject().getJSONObject("credentials").getString("sessionToken");
        String cloudEndPoint = cloudCredResponse.getObject().getString("endpoint");
        System.out.println("Credentials:");
        
        System.out.println("\taccessKeyId: "+accessKeyId);
        System.out.println("\tsecretKey: "+secretKey);
        System.out.println("\tsessionToken: "+sessionToken);
        System.out.println("\tendpoint: "+cloudEndPoint);
        
        System.out.println("\n4. Retrieve messages ...");
        System.out.println("5. Decrypt messages ...");
        app.RetrieveMessage(accessKeyId, secretKey, sessionToken, cloudEndPoint, cryptographyKey);
        
        
        
        System.out.println("\n6. Unsubscribe ... ");
        
        app.UnSubscribeNewsHeadlines(token, subscriptionID);
        		
    }

    public void UnSubscribeNewsStories(String token, String subscriptionID)
    {
    	
    	try {
			HttpResponse<String> response = Unirest.delete("https://api.refinitiv.com/alerts/v1/news-stories-subscriptions?subscriptionID="+subscriptionID)
				.header("Authorization", "Bearer "+token)
				.asString();
			
		} catch (UnirestException ex) {
			System.out.println(ex.toString());
        	System.exit(1);		  
		}
    }
    public void UnSubscribeNewsHeadlines(String token, String subscriptionID)
    {
    	
    	try {
			HttpResponse<String> response = Unirest.delete("https://api.refinitiv.com/alerts/v1/news-headlines-subscriptions?subscriptionID="+subscriptionID)
				.header("Authorization", "Bearer "+token)
				.asString();
			
		} catch (UnirestException ex) {
			System.out.println(ex.toString());
        	System.exit(1);		  
		}
    }
    public void RetrieveMessage(String accesssKeyId, String secretKey, String sessionToken, String endpoint, String cryptographyKey) {
    	
    	AwsCredentials credentials = AwsSessionCredentials.create(accesssKeyId, secretKey, sessionToken);
    	

    	SqsClient sqsClient = SqsClient.builder()
    	  .region(Region.US_EAST_1)    	
    	  .credentialsProvider(()->credentials)  
    	  //.httpClientBuilder(UrlConnectionHttpClient.builder()
          //        .socketTimeout(Duration.ofMinutes(5))
          //        .proxyConfiguration(proxy -> proxy.endpoint(URI.create("http://localhost:8080"))))    	 
    	  .build();
    	
    	System.out.println(endpoint);
    	// Receive messages from the queue
    	for(int i=1;i<=10;i++) {
    	
	        ReceiveMessageRequest receiveRequest = ReceiveMessageRequest.builder()
	            .queueUrl(endpoint)
	            .maxNumberOfMessages(10)
	            .waitTimeSeconds(20)
	            .build();
	        
	        List<Message> messages = sqsClient.receiveMessage(receiveRequest).messages();
	        for (Message m : messages) {
	            //System.out.println("\n" +m.body());
	            try {
	            	
	            	 String s = new String(Decrypt(cryptographyKey, m.body()), StandardCharsets.UTF_8);
	            	 
	            	 JSONObject jsonObj = new JSONObject(s);
	            	 String timestamp = jsonObj.getString("sourceTimestamp");
	            	 String headline = jsonObj.getJSONObject("payload").
	            			 getJSONObject("newsMessage").
	            			 getJSONObject("itemSet").
	            			 getJSONArray("newsItem").getJSONObject(0).
	            			 getJSONObject("itemMeta").
	            			 getJSONArray("title").getJSONObject(0).
	            			 getString("$");
	              	 System.out.println(timestamp+": "+headline);
				} catch (Exception ex) {
					System.out.println(ex.toString());
		        	System.exit(1);		        	
				}
	        }
    	}
	
    	
        
//    	AmazonSQS sqs = AmazonSQSClientBuilder.standard()
//    			  .withCredentials(new AWSStaticCredentialsProvider(credentials))
//    			  .withRegion(Regions.US_EAST_1)
//    			  .build();

    }
    
    public  byte[] Decrypt(String key, String source) throws Exception {
        int GCM_AAD_LENGTH = 16;
        int GCM_TAG_LENGTH = 16;
        int GCM_NONCE_LENGTH = 12;

        byte[] decodedKey = Base64.getDecoder().decode(key);
        byte[] decodedSource = Base64.getDecoder().decode(source);

        byte[] aad = new byte[GCM_AAD_LENGTH];
        System.arraycopy(decodedSource, 0, aad, 0, GCM_AAD_LENGTH);

        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(aad, GCM_AAD_LENGTH - GCM_NONCE_LENGTH, nonce, 0, GCM_NONCE_LENGTH);

        byte[] tag = new byte[GCM_TAG_LENGTH];
        System.arraycopy(decodedSource, decodedSource.length - GCM_TAG_LENGTH, tag, 0, GCM_TAG_LENGTH);

        byte[] encMessage = new byte[decodedSource.length - GCM_AAD_LENGTH];
        System.arraycopy(decodedSource, GCM_AAD_LENGTH, encMessage, 0, encMessage.length);

        SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParams = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParams);
        cipher.updateAAD(aad);

        byte[] decMessage = cipher.doFinal(encMessage);

        //byte[] authenticated = cipher.doFinal(tag);
        //if (!MessageDigest.isEqual(authenticated, tag)) {
         //   throw new Exception("Authentication tag mismatch!");
        //}

        return decMessage;
    }

    public JsonNode GetCloudCredential(String token, String endpoint) {
    	
    	
    	try {
			HttpResponse<JsonNode> response = Unirest.get("https://api.refinitiv.com/auth/cloud-credentials/v1/?endpoint="+endpoint)
			    .header("Authorization", "Bearer "+token)
			    .asJson();
			return response.getBody();
		} catch (UnirestException ex) {
			System.out.println(ex.toString());
        	System.exit(1);
        	return null;
		}

    }
    
    public JsonNode SubscribeNewsStories(String token) {
    	
    	try {
			HttpResponse<JsonNode> response = Unirest.post("https://api.refinitiv.com/alerts/v1/news-stories-subscriptions")
			    .header("content-type", "application/json")
			    .header("Authorization", "Bearer "+token)
			    .body("{\"transport\":{\"transportType\":\"AWS-SQS\"}}")
			    .asJson();
			return response.getBody();
		} catch (UnirestException ex) {			
			System.out.println(ex.toString());
        	System.exit(1);
        	return null;
		}   	
    	
    }
    public JsonNode SubscribeNewsHeadlines(String token) {
    	
    	try {
			HttpResponse<JsonNode> response = Unirest.post("https://api.refinitiv.com/alerts/v1/news-headlines-subscriptions")
			    .header("content-type", "application/json")
			    .header("Authorization", "Bearer "+token)
			    .body("{\"transport\":{\"transportType\":\"AWS-SQS\"},\"filter\":{\"operator\":\"and\",\"operands\":[{\"type\":\"language\",\"value\":\"L:en\"}],\"type\":\"operator\"}}")
			    .asJson();
			return response.getBody();
		} catch (UnirestException ex) {			
			System.out.println(ex.toString());
        	System.exit(1);
        	return null;
		}  	
    	
    }
    public String GetToken(String username, String password, String clientId) {
    	
    	try {
           
            HttpResponse<JsonNode> response = Unirest.post("https://api.refinitiv.com/auth/oauth2/v1/token")
              .header("Content-Type", "application/x-www-form-urlencoded")
              .field("username", username)
              .field("password", password)
              .field("grant_type", "password")
              .field("scope", "trapi")
              .field("takeExclusiveSignOnControl", "true")
              .field("client_id", clientId)
              .asJson();
            return response.getBody().getObject().getString("access_token");
            
            }catch (Exception ex) {
            	System.out.println(ex.toString());
            	System.exit(1);
            	return null;
            }

    }
}
