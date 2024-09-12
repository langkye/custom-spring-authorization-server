package sample.config.provider.sms;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = SmsAuthenticationTokenDeserializer.class)
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
@Deprecated
public class SmsAuthenticationTokenMixin {
}
