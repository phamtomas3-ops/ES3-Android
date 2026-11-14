pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "ES3"
include(":app", ":core:common", ":core:crypto", ":core:format", ":core:compression", ":legacy:easysave3")
