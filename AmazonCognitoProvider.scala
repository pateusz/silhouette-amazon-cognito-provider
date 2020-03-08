package modules

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.api.util.HTTPLayer
import com.mohiva.play.silhouette.impl.exceptions.ProfileRetrievalException
import com.mohiva.play.silhouette.impl.providers._
import play.api.libs.json.{JsObject, JsValue}

import scala.concurrent.Future

import modules.AmazonCognitoProvider._

/**
 * Base AmazonCognito OAuth2 Provider.
 *
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide
 */
trait BaseAmazonCognitoProvider extends OAuth2Provider {

  /**
   * The content type to parse a profile from.
   */
  override type Content = JsValue

  /**
   * The provider ID.
   */
  override val id: String = ID

  /**
   * Defines the URLs that are needed to retrieve the profile data.
   */
  override protected val urls = Map("api" -> settings.apiURL.getOrElse(API))

  /**
   * Builds the social profile.
   *
   * @param authInfo The auth info received from the provider.
   * @return On success the build social profile, otherwise a failure.
   */
  override protected def buildProfile(authInfo: OAuth2Info): Future[Profile] = {
    httpLayer.url(urls("api").format(settings.customProperties("domainName")))
      .withHttpHeaders(("Authorization", s"Bearer ${authInfo.accessToken}"))
      .get().flatMap { response =>
      val json = response.json
      (json \ "error").asOpt[JsObject] match {
        case Some(error) =>
          val errorMsg = (error \ "message").as[String]
          val errorType = (error \ "type").as[String]
          val errorCode = (error \ "code").as[Int]

          throw new ProfileRetrievalException(SpecifiedProfileError.format(id, errorMsg, errorType, errorCode))
        case _ => profileParser.parse(json, authInfo)
      }
    }
  }
}

/**
 * The profile parser for the common social profile.
 */
class AmazonCognitoProfileParser extends SocialProfileParser[JsValue, CommonSocialProfile, OAuth2Info] {

  /**
   * Parses the social profile.
   *
   * @param json     The content returned from the provider.
   * @param authInfo The auth info to query the provider again for additional data.
   * @return The social profile from given result.
   */
  override def parse(json: JsValue, authInfo: OAuth2Info): Future[CommonSocialProfile] = Future.successful {
  //     may need adjustments according to cognito config
    val userID = (json \ "username").as[String]
    val firstName = (json \ "given_name").asOpt[String]
    val lastName = (json \ "family_name").asOpt[String]
    val fullName = (json \ "username").asOpt[String]
    val email = (json \ "email").asOpt[String]

    CommonSocialProfile(
      loginInfo = LoginInfo(ID, userID),
      firstName = firstName,
      lastName = lastName,
      fullName = fullName,
      email = email)
  }
}

/**
 * The AmazonCognito OAuth2 Provider.
 *
 * @param httpLayer    The HTTP layer implementation.
 * @param stateHandler The state provider implementation.
 * @param settings     The provider settings.
 */
class AmazonCognitoProvider(
                          protected val httpLayer: HTTPLayer,
                          protected val stateHandler: SocialStateHandler,
                          val settings: OAuth2Settings)
  extends BaseAmazonCognitoProvider with CommonSocialProfileBuilder {

  /**
   * The type of this class.
   */
  override type Self = AmazonCognitoProvider

  /**
   * The profile parser implementation.
   */
  override val profileParser = new AmazonCognitoProfileParser

  /**
   * Gets a provider initialized with a new settings object.
   *
   * @param f A function which gets the settings passed and returns different settings.
   * @return An instance of the provider initialized with new settings.
   */
  override def withSettings(f: Settings => Settings) = new AmazonCognitoProvider(httpLayer, stateHandler, f(settings))
}

/**
 * The companion object.
 */
object AmazonCognitoProvider {

  /**
   * The error messages.
   */
  val SpecifiedProfileError = "[Silhouette][%s] Error retrieving profile information. Error message: %s, type: %s, code: %s"

  /**
   * The AmazonCognito constants.
   */
  val ID = "cognito"
  val API = "https://%s.auth.eu-central-1.amazoncognito.com/oauth2/userInfo"
}
