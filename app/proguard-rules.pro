# Sentinel uses no reflection-based serialization (findings are stored with org.json by hand),
# so the default Android/Compose rules bundled with the libraries are sufficient.

# Keep line numbers so release crash reports in Play Console are readable.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
