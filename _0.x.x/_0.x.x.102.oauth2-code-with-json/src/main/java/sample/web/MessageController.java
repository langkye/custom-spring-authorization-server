package sample.web;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@RestController
@RequestMapping("/api")
public class MessageController {

    @RequestMapping("/message")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object userResource() {
        return new HashMap<String, Object>() {{
           put("resource", "user"); 
        }};
    }
}
