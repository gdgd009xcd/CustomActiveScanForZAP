import org.zaproxy.gradle.addon.AddOnStatus


version = "0.8.11"
description = "a Active Scanner with custmizable rules"

val jar by tasks.getting(Jar::class) {
    manifest {
        attributes["Multi-Release"] = "true"
    }
}

zapAddOn {
    addOnName.set("CustomActiveScanForZAP")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.13.0")

    manifest {
        author.set("gdgd009xcd")
        url.set("https://gdgd009xcd.github.io/CustomActiveScanForZAP")
        repo.set("https://github.com/gdgd009xcd/CustomActiveScanForZAP")

        /**
        helpSet {
            // ${zapAddOn.addOnId.get()} is the subproject folder name "customactivescan" in addOns project folder.
            val resourcesPath = "org.zaproxy.zap.extension.${zapAddOn.addOnId.get()}.resources."
            // helpset root src path is "src/main/javahelp". you must put helpsets under this directory.
            //
            // baseName and localToken are used for determinating javahelp helpset(.hs)  file path
            // In English (default) locale, %LC% token is convert to ""
            // ${resourcesPath}help.helpset.hs
            // In ja_JP locale, %LC% token is convert to "_ja_JP" then helpset file path is:
            // ${resourcesPath}help_ja_JP.helpset_ja_JP.hs
            // * if you use %LC% locale token, then you must provide "all" locale specific helpset files for ZAP.
            //   otherwise you may remove %LC% to support any locale helpset in English only.
            // * if you comment out this helpSet function entirely,
            //   zaproxy expects the help directory to be in the following path:
            //
            //   ${resourcesPath}help
            //                   help_ja_JP
            //                                                    ...
            //   ${resourcesPath} == org.zaproxy.zap.extension.customactivescan.resources.
            //                    == [this addon's Extension package name].resources.
            //   ** Extension package name is the package name of this addon's Extension class file inherit from ExtensionAdaptor
            //      e.g. The package name of ExtensionAscanRules class.
            //   ** this help directory hierarchy will be used for providing localization help by crowdin in the future.
            //
            // ----locale supported helpset configurations.---
            baseName.set("${resourcesPath}help%LC%.helpset")
            localeToken.set("%LC%")
            // ---- no locale supported(English only) configurations.---
            //baseName.set("${resourcesPath}help.helpset")
            //localeToken.set("")
        }
        **/
    }
}

dependencies {
    //implementation(files("../../../CustomActiveScanLib/out/artifacts/CustomActiveScanLib_jar/CustomActiveScanLib.jar"))
    implementation("com.google.code.gson:gson:2.9.0")
    testImplementation("org.apache.commons:commons-lang3:3.9")
}

tasks {
    val sourcesJar by creating(Jar::class) {
        archiveClassifier.set("sources")
        from(sourceSets.main.get().allSource)
    }

    artifacts {
        archives(sourcesJar)
        // archives(jar)
    }
}

spotless {
    java {
        clearSteps()
        // Don't enforce
        targetExclude("**/*.java")
    }
}
