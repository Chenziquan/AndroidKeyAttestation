# AndroidKeyAttestation

The AndroidKeyAttestation uses hardware-based security features to validate the identity of a device along with authenticity and integrity of the operating system.
It will verify that the device is running the stock operating system with the bootloader locked and that no tampering with the operating system has occurred.
A downgrade to a previous version will also be detected. It builds upon the hardware-based verification of the operating system by chaining verification to the app
 to perform software-based sanity checks and gather additional information about device state and configuration beyond what the hardware can attest to directly.


# Download

build.gradle of project

```groovy
buildscript {
    repositories {
        google()
        jcenter()
        maven {
            url 'https://openrepo.paxengine.com.cn/api/v4/projects/20/packages/maven'
            name "GitLab"
            credentials(HttpHeaderCredentials) {
                name = 'Deploy-Token'
                value = 'tKxMYSwBrxYcDZyVzZAm'
            }
            authentication {
                header(HttpHeaderAuthentication)
            }
        }
    }
}

allprojects {
    repositories {
        google()
        jcenter()
        maven {
            url 'https://openrepo.paxengine.com.cn/api/v4/projects/20/packages/maven'
            name "GitLab"
            credentials(HttpHeaderCredentials) {
                name = 'Deploy-Token'
                value = 'tKxMYSwBrxYcDZyVzZAm'
            }
            authentication {
                header(HttpHeaderAuthentication)
            }
        }
    }
}
```

build.gradle of module.

```groovy
implementation 'com.pax.jc:androidkeyattestation:1.0.0'
```

# Sample

```kotlin
private fun attestation() {
    Thread {
        val keyAttestation = KeyAttestation.getInstance()
        val attestationResult = keyAttestation.attestation(this)
        println("KeyAttestationResult:${attestationResult.boolean}")
        println("KeyAttestationError:${attestationResult.error}")
    }.start()
}
```