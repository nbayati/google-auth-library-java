package com.google.auth.credentialaccessboundary;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.CredentialAccessBoundary;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.OAuth2CredentialsWithRefresh;
import com.google.auth.oauth2.ServiceAccountCredentials;
import dev.cel.common.CelValidationException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;

public class ManualTesting {
  private static final String GCS_BUCKET_NAME = "client-side-cab";
  private static final String GCS_OBJECT_NAME_WITH_PERMISSION = "client-side-cab-first-file";
  private static final String GCS_OBJECT_NAME_WITHOUT_PERMISSION = "client-side-cab-second-file";

  // This Credential Access Boundary enables the objectViewer permission to the specified object in
  // the specified bucket.
  private static final CredentialAccessBoundary CREDENTIAL_ACCESS_BOUNDARY =
      CredentialAccessBoundary.newBuilder()
          .addRule(
              CredentialAccessBoundary.AccessBoundaryRule.newBuilder()
                  .setAvailableResource(
                      String.format(
                          "//storage.googleapis.com/projects/_/buckets/%s", GCS_BUCKET_NAME))
                  .addAvailablePermission("inRole:roles/storage.objectViewer")
                  .setAvailabilityCondition(
                      CredentialAccessBoundary.AccessBoundaryRule.AvailabilityCondition.newBuilder()
                          .setExpression(
                              String.format(
                                  "resource.name.startsWith('projects/_/buckets/%s/objects/%s')",
                                  GCS_BUCKET_NAME, GCS_OBJECT_NAME_WITH_PERMISSION))
                          .build())
                  .build())
          .build();

  private static final String options =
      "generate\nrefresh_margin\nminimum_lifetime\nerror_null_source\nerror_negative_margin\n";

  public static void main(String[] args)
      throws IOException, GeneralSecurityException, CelValidationException {
    if (args.length == 0) {
      System.out.println("Please provide an argument to run the test. Available options are: ");
      System.out.println(options);
      return;
    }

    GoogleCredentials sourceCredentials =
        GoogleCredentials.getApplicationDefault()
            .createScoped("https://www.googleapis.com/auth/cloud-platform");

    if (!(sourceCredentials instanceof ServiceAccountCredentials)) {
      throw new IllegalArgumentException(
          "Client-side CAB currently only supports Service Account credentials. "
              + "Provided credential type: "
              + sourceCredentials.getClass().getSimpleName());
    }

    ClientSideCredentialAccessBoundaryFactory factory;
    String type = args[0];
    long minutes = 59;
    long seconds = 57;
    AccessToken accessToken;

    switch (type) {
      case "generate":
        System.out.println(
            "- Running `generate`..\n- Expect the first object retrieval to succeed and the second one to fail,"
                + " as the generated token only has access to the first one.\n   ---------------------------------");
        OAuth2CredentialsWithRefresh.OAuth2RefreshHandler refreshHandler =
            new OAuth2CredentialsWithRefresh.OAuth2RefreshHandler() {
              @Override
              public AccessToken refreshAccessToken() throws IOException {
                ServiceAccountCredentials sourceCredentials =
                    (ServiceAccountCredentials)
                        GoogleCredentials.getApplicationDefault()
                            .createScoped("https://www.googleapis.com/auth/cloud-platform");

                ClientSideCredentialAccessBoundaryFactory factory =
                    ClientSideCredentialAccessBoundaryFactory.newBuilder()
                        .setSourceCredential(sourceCredentials)
                        .build();

                try {
                  return factory.generateToken(CREDENTIAL_ACCESS_BOUNDARY);
                } catch (CelValidationException | GeneralSecurityException e) {
                  System.out.println(e.getMessage());
                  throw new RuntimeException(e);
                }
              }
            };

        OAuth2CredentialsWithRefresh credentials =
            OAuth2CredentialsWithRefresh.newBuilder().setRefreshHandler(refreshHandler).build();

        // Attempt to retrieve the object that the downscoped token has access to.
        retrieveObjectFromGcs(credentials, GCS_BUCKET_NAME, GCS_OBJECT_NAME_WITH_PERMISSION);

        try {
          // Attempt to retrieve the object that the downscoped token does NOT have access to.
          retrieveObjectFromGcs(credentials, GCS_BUCKET_NAME, GCS_OBJECT_NAME_WITHOUT_PERMISSION);
        } catch (IOException e) {
          System.out.println(e.getMessage());
        }
        break;

      case "error_null_source_credential":
        factory = ClientSideCredentialAccessBoundaryFactory.newBuilder().build();
        factory.refreshCredentialsIfRequired();

        break;

      case "error_negative_refresh_margin":
        factory =
            ClientSideCredentialAccessBoundaryFactory.newBuilder()
                .setSourceCredential(sourceCredentials)
                .setRefreshMargin(Duration.ofMinutes(-1))
                .build();
        factory.refreshCredentialsIfRequired();
        break;
      case "minimum_lifetime":
        Duration minimumTokenLifetime = Duration.ofMinutes(minutes).plusSeconds(seconds);
        System.out.printf(
            "-Creating a factory with minimumLifetime of %d minutes and %d seconds.\n",
            minutes, seconds);
        factory =
            ClientSideCredentialAccessBoundaryFactory.newBuilder()
                .setSourceCredential(sourceCredentials)
                .setMinimumTokenLifetime(minimumTokenLifetime)
                .build();

        System.out.println("-Calling generateToken once so the intermediate token gets generated.");
        accessToken = factory.generateToken(CREDENTIAL_ACCESS_BOUNDARY);
        System.out.println("-intermediate token populated and CAB token generated.");
        final long originalIntermediateTokenExpiration =
            factory.getIntermediateAccessToken().getExpirationTime().getTime();
        printRemainingTime("generated CAB token", accessToken.getExpirationTime().getTime());
        printRemainingTime("intermediate token", originalIntermediateTokenExpiration);

        System.out.println("-Sleeping for 2 seconds to shorten intermediate token lifetime.");
        try {
          Thread.sleep(2001);
        } catch (InterruptedException e) {
          System.out.println(e.getMessage());
        }

        System.out.println(
            "-Calling generateToken again.\n"
                + "   We expect the new generated token to have a remaining lifetime which is  \n"
                + "   is bigger than MinimumTokenLifetime.");
        accessToken = factory.generateToken(CREDENTIAL_ACCESS_BOUNDARY);
        printRemainingTime(
            "intermediate token",
            factory.getIntermediateAccessToken().getExpirationTime().getTime());

        printRemainingTime("new generated CAB token", accessToken.getExpirationTime().getTime());
        break;

      case "refresh_margin":
        Duration refreshMargin = Duration.ofMinutes(minutes).plusSeconds(seconds);

        System.out.printf(
            "-Creating a factory with refreshMargin of %d minutes and %d seconds.\n",
            minutes, seconds);
        factory =
            ClientSideCredentialAccessBoundaryFactory.newBuilder()
                .setSourceCredential(sourceCredentials)
                .setRefreshMargin(refreshMargin)
                .build();

        System.out.println("-Calling generateToken once so the intermediate token gets generated.");
        factory.generateToken(CREDENTIAL_ACCESS_BOUNDARY);

        System.out.println("-Sleeping for 2 seconds to shorten intermediate token lifetime.");
        try {
          Thread.sleep(2001);
        } catch (InterruptedException e) {
          System.out.println(e.getMessage());
        }

        System.out.println(
            "-Calling generateToken again.\n"
                + "   This call will start an async refresh due to the refreshMargin being set.");
        factory.generateToken(CREDENTIAL_ACCESS_BOUNDARY);
        printRemainingTime(
            "intermediate token",
            factory.getIntermediateAccessToken().getExpirationTime().getTime());
        System.out.println("-Sleeping for a second to allow background refresh to finish.");
        try {
          Thread.sleep(1001);
        } catch (InterruptedException e) {
          System.out.println(e.getMessage());
        }
        System.out.println(
            "-After Sleep! Expect to see intermediate token's lifetime has increased.");
        printRemainingTime(
            "intermediate token",
            factory.getIntermediateAccessToken().getExpirationTime().getTime());
        break;
      default:
        System.out.println("Not a valid option! Please choose from one of the following:");
        System.out.println(options);
        break;
    }
  }

  private static void printRemainingTime(String name, long expirationTime) {
    long millis = expirationTime - Clock.SYSTEM.currentTimeMillis();
    if (millis < 0) {
      System.out.println("Expiration Time is in the past!");
      return;
    }

    Duration duration = Duration.ofMillis(millis);
    long minutes = (duration.getSeconds() % 3600) / 60; // Calculate remaining minutes
    long seconds = duration.getSeconds() % 60; // Calculate remaining seconds
    System.out.printf(
        "-Remaining lifetime of %s: %d minutes, %d seconds%n", name, minutes, seconds);
  }

  public static void retrieveObjectFromGcs(
      Credentials credentials, String bucketName, String objectName) throws IOException {
    System.out.println("Retrieving " + objectName + " from GCS bucket " + bucketName + ":");
    String url =
        String.format(
            "https://storage.googleapis.com/storage/v1/b/%s/o/%s", bucketName, objectName);

    HttpCredentialsAdapter credentialsAdapter = new HttpCredentialsAdapter(credentials);
    HttpRequestFactory requestFactory =
        new NetHttpTransport().createRequestFactory(credentialsAdapter);
    HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(url));

    JsonObjectParser parser = new JsonObjectParser(GsonFactory.getDefaultInstance());
    request.setParser(parser);

    HttpResponse response = request.execute();
    System.out.println("Status code: " + response.getStatusCode());
    System.out.println(response.parseAsString());
  }
}
