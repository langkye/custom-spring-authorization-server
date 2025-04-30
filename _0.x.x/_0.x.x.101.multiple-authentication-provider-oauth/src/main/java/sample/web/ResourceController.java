package sample.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@RestController
@RequestMapping("/api/resource")
public class ResourceController {
    @GetMapping("/userResource")
    @PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object userResource() {
        return new HashMap<String, Object>() {{
           put("resource", "user"); 
        }};
    }
    @GetMapping("/adminResource")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'admin') or hasAnyRole('ADMIN', 'admin')")
    public Object adminResource() {
        return new HashMap<String, Object>() {{
           put("resource", "admin"); 
        }};
    }
}
