package sample.config.provider.sms;


import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Deprecated
public class SmsAuthenticationTokenDeserializer extends JsonDeserializer<SmsAuthenticationToken> {
    @Override
    public SmsAuthenticationToken deserialize(JsonParser parser, DeserializationContext context) throws IOException, JacksonException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);
        return deserialize(parser, mapper, root);
    }

    private SmsAuthenticationToken deserialize(JsonParser parser, ObjectMapper mapper, JsonNode root)
            throws JsonParseException {
        JsonNode principal = JsonNodeUtils.findObjectNode(root, "principal");
        if (!Objects.isNull(principal)) {
            //String tokenValue = principal.get("tokenValue").textValue();
            //long issuedAt = principal.get("issuedAt").longValue();
            //long expiresAt = principal.get("expiresAt").longValue();
            //Map<String, Object> headers = JsonNodeUtils.findValue(principal, "headers", JsonNodeUtils.STRING_OBJECT_MAP, mapper);
            //Map<String, Object> claims = new HashMap<>();
            //claims.put("claims", principal.get("claims"));
            //Jwt jwt = new Jwt(tokenValue, Instant.ofEpochMilli(issuedAt), Instant.ofEpochMilli(expiresAt), headers, claims);
            // todo
            return new SmsAuthenticationToken();
        }
        return null;
    }
    
    static abstract class JsonNodeUtils {

        static final TypeReference<Set<String>> STRING_SET = new TypeReference<Set<String>>() {
        };

        static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP = new TypeReference<Map<String, Object>>() {
        };

        static String findStringValue(JsonNode jsonNode, String fieldName) {
            if (jsonNode == null) {
                return null;
            }
            JsonNode value = jsonNode.findValue(fieldName);
            return (value != null && value.isTextual()) ? value.asText() : null;
        }

        static <T> T findValue(JsonNode jsonNode, String fieldName, TypeReference<T> valueTypeReference,
                               ObjectMapper mapper) {
            if (jsonNode == null) {
                return null;
            }
            JsonNode value = jsonNode.findValue(fieldName);
            return (value != null && value.isContainerNode()) ? mapper.convertValue(value, valueTypeReference) : null;
        }

        static JsonNode findObjectNode(JsonNode jsonNode, String fieldName) {
            if (jsonNode == null) {
                return null;
            }
            JsonNode value = jsonNode.findValue(fieldName);
            return (value != null && value.isObject()) ? value : null;
        }

    }
}
