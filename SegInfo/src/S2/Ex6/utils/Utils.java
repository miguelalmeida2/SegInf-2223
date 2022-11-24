package S2.Ex6.utils;

import java.io.InputStream;

public class Utils {
    
    public static InputStream readResourceFile(String path) {
        return ClassLoader.getSystemResourceAsStream(path);
    }
    
}
