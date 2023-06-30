package sample.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@RestController
@RequestMapping("/api/resource")
public class ResourceController {
    @GetMapping("/userResource")
    @PreAuthorize("hasAnyAuthority('USER') or hasAnyRole('USER')")
    public Object userResource() {
        return new HashMap<String, Object>() {{
           put("resource", "user"); 
        }};
    }
    @GetMapping("/adminResource")
    @PreAuthorize("hasAnyAuthority('ADMIN') or hasRole('ADMIN')")
    public Object adminResource() {
        return new HashMap<String, Object>() {{
           put("resource", "admin"); 
        }};
    }
}//Authorization
