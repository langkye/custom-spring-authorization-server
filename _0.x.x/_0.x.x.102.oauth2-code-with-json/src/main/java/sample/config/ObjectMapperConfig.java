package sample.config;

import cn.hutool.core.date.DateException;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.DateSerializer;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalTimeSerializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;

import java.io.IOException;
import java.math.BigDecimal;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Configuration
public class ObjectMapperConfig {
    private static final DateTimeFormatter DATETIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    public abstract class TimestampMixin {
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "UTC")
        private java.sql.Timestamp createTime;

        public Timestamp getCreateTime() {
            return createTime;
        }

        public void setCreateTime(Timestamp createTime) {
            this.createTime = createTime;
        }
    }
    
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();

        // 启用默认类型处理（非 final 类型），允许反序列化自定义类
        //objectMapper.activateDefaultTyping(
        //        objectMapper.getPolymorphicTypeValidator(),
        //        ObjectMapper.DefaultTyping.NON_FINAL
        //);
        //
        JavaTimeModule javaTimeModule = new JavaTimeModule();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        //序列化日期格式
        javaTimeModule.addSerializer(LocalDateTime.class, new LocalDateTimeSerializer());
        javaTimeModule.addSerializer(LocalDate.class, new LocalDateSerializer());
        javaTimeModule.addSerializer(LocalTime.class, new LocalTimeSerializer());
        javaTimeModule.addSerializer(Date.class, new DateSerializer(false, simpleDateFormat));

        //反序列化日期格式
        javaTimeModule.addDeserializer(LocalDateTime.class, new LocalDateTimeDeserializer());
        javaTimeModule.addDeserializer(LocalDate.class, new LocalDateDeserializer());
        javaTimeModule.addDeserializer(LocalTime.class, new LocalTimeDeserializer());
        javaTimeModule.addDeserializer(Date.class, new DateDeserializer());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        objectMapper.setTimeZone(TimeZone.getTimeZone("Asia/Shanghai"));
        
        
        
        
        // 序列化枚举值
        objectMapper.configure(SerializationFeature.WRITE_ENUMS_USING_TO_STRING, true);
        //忽略value为null时key的输出
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);


        //序列化成json时，将所有的Number、基础数据类型序列化为string，以解决js中的精度丢失。
        SimpleModule simpleModule = new SimpleModule();
        simpleModule.addSerializer(Short.class, ToStringSerializer.instance);
        simpleModule.addSerializer(Short.TYPE, ToStringSerializer.instance);
        
        simpleModule.addSerializer(Integer.class, ToStringSerializer.instance);
        simpleModule.addSerializer(Integer.TYPE, ToStringSerializer.instance);
        
        simpleModule.addSerializer(Long.class, ToStringSerializer.instance);
        simpleModule.addSerializer(Long.TYPE, ToStringSerializer.instance);

        simpleModule.addSerializer(BigDecimal.class, ToStringSerializer.instance);
        //simpleModule.addSerializer(BigDecimal.TYPE, ToStringSerializer.instance);

        simpleModule.addSerializer(Double.class, ToStringSerializer.instance);
        simpleModule.addSerializer(Double.TYPE, ToStringSerializer.instance);

        simpleModule.addSerializer(Float.class, ToStringSerializer.instance);
        simpleModule.addSerializer(Float.TYPE, ToStringSerializer.instance);

        simpleModule.addSerializer(Number.class, ToStringSerializer.instance);
        //simpleModule.addSerializer(Number.TYPE, ToStringSerializer.instance);

        simpleModule.addSerializer(Boolean.class, ToStringSerializer.instance);
        simpleModule.addSerializer(Boolean.TYPE, ToStringSerializer.instance);

        objectMapper.addMixIn(java.sql.Timestamp.class, TimestampMixin.class);
        
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader); 
        
        objectMapper.registerModule(simpleModule);
        objectMapper.registerModule(javaTimeModule);
        //objectMapper.registerModule(new CoreJackson2Module()); // SecurityJackson2Modules.getModules包含CoreJackson2Module
        objectMapper.registerModules(securityModules);

        // 禁用 @class 属性的多态性支持（显示定义的除外：@JsonTypeInfo、@JsonSubTypes）
        objectMapper.deactivateDefaultTyping();
        
        return objectMapper;
    }


    /**
     * Date反序列化
     */
    private  static class DateDeserializer extends JsonDeserializer<Date> {
        @Override
        public Date deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
            String date = jsonParser.getText();
            try {
                //return simpleDateFormat.parse(date);
                return cn.hutool.core.date.DateUtil.parse(date);
                //} catch (ParseException e) {
            } catch (DateException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * LocalDateTime序列化
     */
    private static class LocalDateTimeSerializer extends JsonSerializer<LocalDateTime> {

        @Override
        public void serialize(LocalDateTime value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeString(value.format(DATETIME_FORMATTER));
        }
    }

    /**
     * LocalDateTime反序列化
     */
    private static class LocalDateTimeDeserializer extends JsonDeserializer<LocalDateTime> {

        @Override
        public LocalDateTime deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            return LocalDateTime.parse(p.getValueAsString(), DATETIME_FORMATTER);
        }
    }

    /**
     * LocalDate序列化
     */
    private static class LocalDateSerializer extends JsonSerializer<LocalDate> {

        @Override
        public void serialize(LocalDate value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeString(value.format(DATE_FORMATTER));
        }
    }

    /**
     * LocalDate反序列化
     */
    private static class LocalDateDeserializer extends JsonDeserializer<LocalDate> {

        @Override
        public LocalDate deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            return LocalDate.parse(p.getValueAsString(), DATE_FORMATTER);
        }
    }

    /**
     * LocalTime序列化
     */
    private static class LocalTimeSerializer extends JsonSerializer<LocalTime> {

        @Override
        public void serialize(LocalTime value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeString(value.format(TIME_FORMATTER));
        }
    }

    /**
     * LocalTime反序列化
     */
    private static class LocalTimeDeserializer extends JsonDeserializer<LocalTime> {

        @Override
        public LocalTime deserialize(JsonParser p, DeserializationContext ctx) throws IOException {
            return LocalTime.parse(p.getValueAsString(), TIME_FORMATTER);
        }
    }
}
