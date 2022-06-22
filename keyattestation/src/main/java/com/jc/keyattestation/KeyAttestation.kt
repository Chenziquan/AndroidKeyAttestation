package com.jc.keyattestation

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.Resources
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.TextUtils
import android.util.Base64
import androidx.preference.PreferenceManager
import com.google.common.collect.ImmutableMap
import com.google.common.collect.ImmutableSet
import com.google.common.hash.Hashing
import com.google.common.io.BaseEncoding
import com.jc.keyattestation.attestation.Attestation
import com.jc.keyattestation.attestation.AuthorizationList
import com.jc.keyattestation.attestation.RootOfTrust
import com.pax.jc.keyattestation.R
import java.io.IOException
import java.io.InputStream
import java.lang.StringBuilder
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.*
import javax.security.auth.x500.X500Principal

/**
 * @author JQChen.
 * @date on 11/10/2021.
 */
class KeyAttestation private constructor() {
    companion object {
        // Global preferences
        private const val KEY_CHALLENGE_INDEX = "challenge_index"
        private const val KEYSTORE_ALIAS_PERSISTENT_PREFIX = "persistent_attestation_key_"
        private const val KEYSTORE_ALIAS_FRESH = "fresh_attestation_key"
        private const val STRING_BOX = "StrongBox"

        private const val CHALLENGE_LENGTH = 32

        private const val CLOCK_SKEW_MS = 60 * 1000
        private val EXPIRE_OFFSET_MS: Int = 5 * 60 * 1000 + CLOCK_SKEW_MS
        private const val EC_CURVE = "secp256r1"
        private const val KEY_DIGEST = KeyProperties.DIGEST_SHA256

        private val FINGERPRINT_HASH_FUNCTION = Hashing.sha256()
        private val FINGERPRINT_LENGTH: Int = FINGERPRINT_HASH_FUNCTION.bits() / 8

        // Developer previews set osVersion to 0 as a placeholder value.
        private const val DEVELOPER_PREVIEW_OS_VERSION = 0
        private const val OS_VERSION_MINIMUM = 80000
        private const val OS_PATCH_LEVEL_MINIMUM = 201801
        private const val VENDOR_PATCH_LEVEL_MINIMUM = 201808
        private const val BOOT_PATCH_LEVEL_MINIMUM = 201809

        private val IS_STRONGBOX_SUPPORTED: Boolean = ImmutableSet.of(
            "Pixel 3",
            "Pixel 3 XL",
            "Pixel 3a",
            "Pixel 3a XL",
            "Pixel 4",
            "Pixel 4 XL",
            "Pixel 4a",
            "Pixel 4a (5G)",
            "Pixel 5",
            "Pixel 5a",
            "SM-N970U",
            "SM-N975U"
        ).contains(Build.MODEL)

        private val extraPatchLevelMissing = ImmutableSet.of(
            R.string.device_sm_a705fn,
            R.string.device_sm_g970f,
            R.string.device_sm_g975f,
            R.string.device_sm_n970f,
            R.string.device_sm_n970u,
            R.string.device_sm_n975u,
            R.string.device_sm_t510
        )

        private val fingerprintsMigration = ImmutableMap
            .builder<String, String>() // GrapheneOS Pixel 3
            .put(
                "0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF",  // v2
                "213AA4392BF7CABB9676C2680E134FB5FD3E5937D7E607B4EB907CB0A9D9E400"
            ) // v1
            // GrapheneOS Pixel 3 XL
            .put(
                "06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451",  // v2
                "60D551860CC7FD32A9DC65FB3BCEB87A5E5C1F88928026F454A234D69B385580"
            ) // v1
            // Stock OS Pixel 3 and Pixel 3 XL
            .put(
                "61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C",  // v2
                "B799391AFAE3B35522D1EDC5C70A3746B097BDD1CABD59F72BB049705C7A03EF"
            ) // v1
            .build()

        private val fingerprintsCustomOS: ImmutableMap<String, DeviceInfo> =
            ImmutableMap
                .builder<String, DeviceInfo>() // GrapheneOS
                .put(
                    "B094E48B27C6E15661223CEFF539CF35E481DEB4E3250331E973AC2C15CAD6CD",
                    DeviceInfo(
                        R.string.device_pixel_2,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "B6851E9B9C0EBB7185420BD0E79D20A84CB15AB0B018505EFFAA4A72B9D9DAC7",
                    DeviceInfo(
                        R.string.device_pixel_2_xl,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "213AA4392BF7CABB9676C2680E134FB5FD3E5937D7E607B4EB907CB0A9D9E400",  // v1
                    DeviceInfo(
                        R.string.device_pixel_3,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF",  // v2
                    DeviceInfo(
                        R.string.device_pixel_3,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "60D551860CC7FD32A9DC65FB3BCEB87A5E5C1F88928026F454A234D69B385580",  // v1
                    DeviceInfo(
                        R.string.device_pixel_3_xl,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451",  // v2
                    DeviceInfo(
                        R.string.device_pixel_3_xl,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "8FF8B9B4F831114963669E04EA4F849F33F3744686A0B33B833682746645ABC8",
                    DeviceInfo(
                        R.string.device_pixel_3a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "91943FAA75DCB6392AE87DA18CA57D072BFFB80BC30F8FAFC7FFE13D76C5736E",
                    DeviceInfo(
                        R.string.device_pixel_3a_xl,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "80EF268700EE42686F779A47B4A155FE1FFC2EEDF836B4803CAAB8FA61439746",
                    DeviceInfo(
                        R.string.device_pixel_4,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "3F15FDCB82847FED97427CE00563B8F9FF34627070DE5FDB17ACA7849AB98CC8",
                    DeviceInfo(
                        R.string.device_pixel_4_xl,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "9F2454A1657B1B5AD7F2336B39A2611F7A40B2E0DDFD0D6553A359605928DF29",
                    DeviceInfo(
                        R.string.device_pixel_4a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "DCEC2D053D3EC4F1C9BE414AA07E4D7D7CBD12040AD2F8831C994A83A0536866",
                    DeviceInfo(
                        R.string.device_pixel_4a_5g,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "36A99EAB7907E4FB12A70E3C41C456BCBE46C13413FBFE2436ADEE2B2B61120F",
                    DeviceInfo(
                        R.string.device_pixel_5,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "0ABDDEDA03B6CE10548C95E0BEA196FAA539866F929BCDF7ECA84B4203952514",
                    DeviceInfo(
                        R.string.device_pixel_5a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .build()
        private val fingerprintsStock: ImmutableMap<String, DeviceInfo> =
            ImmutableMap
                .builder<String, DeviceInfo>()
                .put(
                    "5341E6B2646979A70E57653007A1F310169421EC9BDD9F1A5648F75ADE005AF1",
                    DeviceInfo(
                        R.string.device_huawei,
                        2,
                        3,
                        false,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "7E2E8CC82A77CA74554457E5DF3A3ED82E7032B3182D17FE17919BC6E989FF09",
                    DeviceInfo(
                        R.string.device_huawei_honor_7a_pro,
                        2,
                        3,
                        false,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "DFC2920C81E136FDD2A510478FDA137B262DC51D449EDD7D0BDB554745725CFE",
                    DeviceInfo(
                        R.string.device_nokia,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "4D790FA0A5FE81D6B352B90AFE430684D9BC817518CD24C50E6343395F7C51F2",
                    DeviceInfo(
                        R.string.device_nokia_3_1,
                        2,
                        3,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "893A17FD918235DB2865F7F6439EB0134A45B766AA452E0675BAC6CFB5A773AA",
                    DeviceInfo(
                        R.string.device_nokia_7_1,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "6101853DFF451FAE5B137DF914D5E6C15C659337F2C405AC50B513A159071958",
                    DeviceInfo(
                        R.string.device_oneplus_6_a6003,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "1B90B7D1449D697FB2732A7D2DFA405D587254593F5137F7B6E64F7A0CE03BFD",
                    DeviceInfo(
                        R.string.device_oneplus_6t_a6013,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "4B9201B11685BE6710E2B2BA8482F444E237E0C8A3D1F7F447FE29C37CECC559",
                    DeviceInfo(
                        R.string.device_oneplus_7_pro_gm1913,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "1962B0538579FFCE9AC9F507C46AFE3B92055BAC7146462283C85C500BE78D82",
                    DeviceInfo(
                        R.string.device_pixel_2,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "171616EAEF26009FC46DC6D89F3D24217E926C81A67CE65D2E3A9DC27040C7AB",
                    DeviceInfo(
                        R.string.device_pixel_2_xl,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "B799391AFAE3B35522D1EDC5C70A3746B097BDD1CABD59F72BB049705C7A03EF",  // v1
                    DeviceInfo(
                        R.string.device_pixel_3_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C",  // v2
                    DeviceInfo(
                        R.string.device_pixel_3_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "E75B86C52C7496255A95FB1E2B1C044BFA9D5FE34DD1E4EEBD752EEF0EA89875",
                    DeviceInfo(
                        R.string.device_pixel_3a_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "AE6316B4753C61F5855B95B9B98484AF784F2E83648D0FCC8107FCA752CAEA34",
                    DeviceInfo(
                        R.string.device_pixel_4_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "879CD3F18EA76E244D4D4AC3BCB9C337C13B4667190B19035AFE2536550050F1",
                    DeviceInfo(
                        R.string.device_pixel_4a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "88265D85BA9E1E2F6036A259D880D2741031ACA445840137395B6D541C0FC7FC",
                    DeviceInfo(
                        R.string.device_pixel_5_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "1DD694CE00BF131AD61CEB576B7DCC41CF7F9B2C418F4C12B2B8F3E9A1EA911D",
                    DeviceInfo(
                        R.string.device_pixel_5a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "72376CAACF11726D4922585732429FB97D0D1DD69F0D2E0770B9E61D14ADDE65",
                    DeviceInfo(
                        R.string.device_sm_a705fn,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "EB1932405227673AEF15F80B90D2F898A0BE4C770F651AEF1762AED31F52AC54",
                    DeviceInfo(
                        R.string.device_sm_g8870,
                        1,
                        2,
                        false /* uses new API */,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "33D9484FD512E610BCF00C502827F3D55A415088F276C6506657215E622FA770",
                    DeviceInfo(
                        R.string.device_sm_g960f,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "266869F7CF2FB56008EFC4BE8946C8F84190577F9CA688F59C72DD585E696488",
                    DeviceInfo(
                        R.string.device_sm_g960_na,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "12E8460A7BAF709F3B6CF41C7E5A37C6EB4D11CB36CF7F61F7793C8DCDC3C2E4",
                    DeviceInfo(
                        R.string.device_sm_g9600,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "D1C53B7A931909EC37F1939B14621C6E4FD19BF9079D195F86B3CEA47CD1F92D",
                    DeviceInfo(
                        R.string.device_sm_g965f,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "A4A544C2CFBAEAA88C12360C2E4B44C29722FC8DBB81392A6C1FAEDB7BF63010",
                    DeviceInfo(
                        R.string.device_sm_g965_msm,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "9D77474FA4FEA6F0B28636222FBCEE2BB1E6FF9856C736C85B8EA6E3467F2BBA",
                    DeviceInfo(
                        R.string.device_sm_g970f,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "08B2B5C6EC8F54C00C505756E1EF516BB4537B2F02D640410D287A43FCF92E3F",
                    DeviceInfo(
                        R.string.device_sm_g975f,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "56D4C8142E89CE302A6D8165BDD3A411969B570D72931356DA3C317FB2CF1504",
                    DeviceInfo(
                        R.string.device_sm_g9750,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "F0FC0AF47D3FE4F27D79CF629AD6AC42AA1EEDE0A29C0AE109A91BBD1E7CD76D",
                    DeviceInfo(
                        R.string.device_sm_j260a,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "410102030405060708090001020304050607080900010203040506070809005A",
                    DeviceInfo(
                        R.string.device_sm_j260f,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "D6B902D9E77DFC0FB3627FFEFA6D05405932EBB3A6ED077874B5E2A0CCBDB632",
                    DeviceInfo(
                        R.string.device_sm_j260t1,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "4558C1AFB30D1B46CB93F85462BC7D7FCF70B0103B9DBB0FE96DD828F43F29FC",
                    DeviceInfo(
                        R.string.device_sm_j337a,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "45E3AB5D61A03915AE10BF0465B186CB5D9A2FB6A46BEFAA76E4483BBA5A358D",
                    DeviceInfo(
                        R.string.device_sm_j337t,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "D95279A8F2E832FD68D919DBF33CFE159D5A1179686DB0BD2D7BBBF2382C4DD3",
                    DeviceInfo(
                        R.string.device_sm_j720f,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "BB053A5F64D3E3F17C4611340FF2BBE2F605B832A9FA412B2C87F2A163ECE2FB",
                    DeviceInfo(
                        R.string.device_sm_j737t1,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "4E0570011025D01386D057B2B382969F804DCD19E001344535CF0CFDB8AD7CFE",
                    DeviceInfo(
                        R.string.device_sm_m205f,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "2A7E4954C9F703F3AC805AC660EA1727B981DB39B1E0F41E4013FA2586D3DF7F",
                    DeviceInfo(
                        R.string.device_sm_n960f,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "173ACFA8AE9EDE7BBD998F45A49231F3A4BDDF0779345732E309446B46B5641B",
                    DeviceInfo(
                        R.string.device_sm_n960u,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "E94BC43B97F98CD10C22CD9D8469DBE621116ECFA624FE291A1D53CF3CD685D1",
                    DeviceInfo(
                        R.string.device_sm_n970f,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "466011C44BBF883DB38CF96617ED35C796CE2552C5357F9230258329E943DB70",
                    DeviceInfo(
                        R.string.device_sm_n970u,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "52946676088007755EB586B3E3F3E8D3821BE5DF73513E6C13640507976420E6",
                    DeviceInfo(
                        R.string.device_sm_n975u,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "F3688C02D9676DEDB6909CADE364C271901FD66EA4F691AEB8B8921195E469C5",
                    DeviceInfo(
                        R.string.device_sm_s367vl,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "106592D051E54388C6E601DFD61D59EB1674A8B93216C65C5B3E1830B73D3B82",
                    DeviceInfo(
                        R.string.device_sm_t510,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "87790149AED63553B768456AAB6DAAD5678CD87BDEB2BF3649467085349C34E0",
                    DeviceInfo(
                        R.string.device_sm_t835,
                        1,
                        2,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "4285AD64745CC79B4499817F264DC16BF2AF5163AF6C328964F39E61EC84693E",
                    DeviceInfo(
                        R.string.device_sony_xperia_xa2,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "54A9F21E9CFAD3A2D028517EF333A658302417DB7FB75E0A109A019646CC5F39",
                    DeviceInfo(
                        R.string.device_sony_xperia_xz1,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "BC3B5E121974113939B8A2FE758F9B923F1D195F038D2FD1C04929F886E83BB5",
                    DeviceInfo(
                        R.string.device_sony_xperia_xz2,
                        2,
                        3,
                        false,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "94B8B4E3260B4BF8211A02CF2F3DE257A127CFFB2E4047D5580A752A5E253DE0",
                    DeviceInfo(
                        R.string.device_sony_xperia_xz2_compact,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "CFBB73FE2B99733B880AC1DFD5BAAA6146EA66B842C8781DA7B36269D4790774",
                    DeviceInfo(
                        R.string.device_sony_xperia_1_III,
                        2,
                        3,
                        false,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "003997903C81E3EFF79EAA3FF54C1BD3AC30699D3665CD7E267F469D87DFB358",
                    DeviceInfo(
                        R.string.device_sony_xperia_1,
                        2,
                        3,
                        false,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "728800FEBB119ADD74519618AFEDB715E1C39FE08A4DE37D249BF54ACF1CE00F",
                    DeviceInfo(
                        R.string.device_blackberry_key2,
                        2,
                        3,
                        true,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "1194659B40EA291245E54A3C4EC4AA5B7077BD244D65C7DD8C0A2DBB9DB1FB35",
                    DeviceInfo(
                        R.string.device_bq_aquaris_x2_pro,
                        2,
                        3,
                        true,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "A9C6758D509600D0EB94FA8D2BF6EE7A6A6097F0CCEF94A755DDE065AA1AA1B0",
                    DeviceInfo(
                        R.string.device_xiaomi_mi_a2,
                        2,
                        3,
                        true,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "6FA710B639848C9D47378937A1AFB1B6A52DDA738BEB6657E2AE70A15B40541A",
                    DeviceInfo(
                        R.string.device_xiaomi_mi_a2_lite,
                        2,
                        3,
                        true,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "84BC8445A29B5444A2D1629C9774C8626DAFF3574D865EC5067A78FAEC96B013",
                    DeviceInfo(
                        R.string.device_xiaomi_mi_9,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "1CC39488D2F85DEE0A8E0903CDC4124CFDF2BE2531ED6060B678057ED2CB89B4",
                    DeviceInfo(
                        R.string.device_htc,
                        2,
                        3,
                        true,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "80BAB060807CFFA45D4747DF1AD706FEE3AE3F645F80CF14871DDBE27E14C30B",
                    DeviceInfo(
                        R.string.device_moto_g7,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "C2224571C9CD5C89200A7311B1E37AA9CF751E2E19753E8D3702BCA00BE1D42C",
                    DeviceInfo(
                        R.string.device_motorola_one_vision,
                        2,
                        3,
                        false,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "1F6D98D1B0E1F1CE1C872BD36C668F9DFDBE0D47594789E1540DF4E6198F657D",
                    DeviceInfo(
                        R.string.device_vivo_1807,
                        2,
                        3,
                        true,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "C55635636999E9D0A0588D24402256B7F9F3AEE07B4F7E4E003F09FF0190AFAE",
                    DeviceInfo(
                        R.string.device_revvl_2,
                        2,
                        3,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "341C50D577DC5F3D5B46E8BFA22C22D1E5FC7D86D4D860E70B89222A7CBFC893",
                    DeviceInfo(
                        R.string.device_oppo_cph1831,
                        2,
                        3,
                        true,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "41BF0A26BB3AFDCCCC40F7B685083522EB5BF1C492F0EC4847F351265313CB07",
                    DeviceInfo(
                        R.string.device_oppo_cph1903,
                        2,
                        3,
                        true,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "7E19E217072BE6CB7A4C6F673FD3FB62DC51B3E204E7475838747947A3920DD8",
                    DeviceInfo(
                        R.string.device_oppo_cph1909,
                        2,
                        3,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "0D5F986943D0CE0D4F9783C27EEBE175BE359927DB8B6546B667279A81133C3C",
                    DeviceInfo(
                        R.string.device_lg_q710al,
                        2,
                        3,
                        false,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "D20078F2AF2A7D3ECA3064018CB8BD47FBCA6EE61ABB41BA909D3C529CB802F4",
                    DeviceInfo(
                        R.string.device_lm_q720,
                        3,
                        4,
                        false /* uses new API */,
                        false,
                        R.string.os_stock
                    )
                )
                .put(
                    "54EC644C21FD8229E3B0066513337A8E2C8EF3098A3F974B6A1CFE456A683DAE",
                    DeviceInfo(
                        R.string.device_rmx1941,
                        2,
                        3,
                        false,
                        true,
                        R.string.os_stock
                    )
                )
                .build()

        private val fingerprintsStrongBoxCustomOS: ImmutableMap<String, DeviceInfo> =
            ImmutableMap
                .builder<String, DeviceInfo>() // GrapheneOS
                .put(
                    "0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF",
                    DeviceInfo(
                        R.string.device_pixel_3,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451",
                    DeviceInfo(
                        R.string.device_pixel_3_xl,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "73D6C63A07610404FE16A4E07DD24E41A70D331E9D3EF7BBA2D087E4761EB63A",
                    DeviceInfo(
                        R.string.device_pixel_3a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "3F36E3482E1FF82986576552CB4FD08AF09F8B09D3832314341E04C42D2919A4",
                    DeviceInfo(
                        R.string.device_pixel_3a_xl,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "80EF268700EE42686F779A47B4A155FE1FFC2EEDF836B4803CAAB8FA61439746",
                    DeviceInfo(
                        R.string.device_pixel_4,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "3F15FDCB82847FED97427CE00563B8F9FF34627070DE5FDB17ACA7849AB98CC8",
                    DeviceInfo(
                        R.string.device_pixel_4_xl,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "9F2454A1657B1B5AD7F2336B39A2611F7A40B2E0DDFD0D6553A359605928DF29",
                    DeviceInfo(
                        R.string.device_pixel_4a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "DCEC2D053D3EC4F1C9BE414AA07E4D7D7CBD12040AD2F8831C994A83A0536866",
                    DeviceInfo(
                        R.string.device_pixel_4a_5g,
                        4,
                        41,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "36A99EAB7907E4FB12A70E3C41C456BCBE46C13413FBFE2436ADEE2B2B61120F",
                    DeviceInfo(
                        R.string.device_pixel_5,
                        4,
                        41,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .put(
                    "0ABDDEDA03B6CE10548C95E0BEA196FAA539866F929BCDF7ECA84B4203952514",
                    DeviceInfo(
                        R.string.device_pixel_5a,
                        4,
                        41,
                        false /* uses new API */,
                        true,
                        R.string.os_graphene
                    )
                )
                .build()
        private val fingerprintsStrongBoxStock: ImmutableMap<String, DeviceInfo> =
            ImmutableMap
                .builder<String, DeviceInfo>()
                .put(
                    "61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C",
                    DeviceInfo(
                        R.string.device_pixel_3_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "8CA89AF1A6DAA74B00810849356DE929CFC4498EF36AF964757BDE8A113BF46D",
                    DeviceInfo(
                        R.string.device_pixel_3a_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "AE6316B4753C61F5855B95B9B98484AF784F2E83648D0FCC8107FCA752CAEA34",
                    DeviceInfo(
                        R.string.device_pixel_4_generic,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "879CD3F18EA76E244D4D4AC3BCB9C337C13B4667190B19035AFE2536550050F1",
                    DeviceInfo(
                        R.string.device_pixel_4a,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "88265D85BA9E1E2F6036A259D880D2741031ACA445840137395B6D541C0FC7FC",
                    DeviceInfo(
                        R.string.device_pixel_5_generic,
                        4,
                        41,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "1DD694CE00BF131AD61CEB576B7DCC41CF7F9B2C418F4C12B2B8F3E9A1EA911D",
                    DeviceInfo(
                        R.string.device_pixel_5a,
                        4,
                        41,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "466011C44BBF883DB38CF96617ED35C796CE2552C5357F9230258329E943DB70",
                    DeviceInfo(
                        R.string.device_sm_n970u,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .put(
                    "9AC63842137D92C119A1B1BE2C9270B9EBB6083BBE6350B7823571942B5869F0",
                    DeviceInfo(
                        R.string.device_sm_n975u,
                        3,
                        4,
                        false /* uses new API */,
                        true,
                        R.string.os_stock
                    )
                )
                .build()


        @Volatile
        private var instance: KeyAttestation? = null

        fun getInstance() = instance ?: synchronized(this) {
            instance ?: KeyAttestation().also { instance = it }
        }
    }

    data class AttestationResult(val boolean: Boolean, val error: String)

    private class DeviceInfo(
        val name: Int, val attestationVersion: Int, val keymasterVersion: Int,
        val rollbackResistant: Boolean, val perUserEncryption: Boolean, val osName: Int
    )

    fun attestation(context: Context): AttestationResult {
        try {
            val msg = attestation(context, null)
            return AttestationResult(true, msg)
        } catch (e: GeneralSecurityException) {
            return AttestationResult(false, e.message ?: "")
        }

    }

    @Throws(GeneralSecurityException::class)
    fun attestation(context: Context, index: String?) :String{
        var keyIndex = index
        val challenge = getChallenge()
        if (TextUtils.isEmpty(keyIndex)) {
            val challengeIndex = getChallengeIndex(context)
            keyIndex = BaseEncoding.base16().encode(challengeIndex)
        }
        val persistentKeystoreAlias = KEYSTORE_ALIAS_PERSISTENT_PREFIX + keyIndex
        val keyStoreProxy = KeyStoreProxy.getInstance(context)
        val hasPersistentKey = keyStoreProxy.isKeyStoreBacked(persistentKeystoreAlias)

        val hasRefreshKey = keyStoreProxy.isKeyStoreBacked(KEYSTORE_ALIAS_FRESH)
        if (hasRefreshKey) {
            keyStoreProxy.deleteKey(KEYSTORE_ALIAS_FRESH)
        }
        val attestationKeystoreAlias: String
        val useStrongBox: Boolean
        if (hasPersistentKey) {
            attestationKeystoreAlias = KEYSTORE_ALIAS_FRESH
            val persistent: X509Certificate =
                keyStoreProxy.getCertificate(persistentKeystoreAlias) as X509Certificate
            val dn: String = persistent.issuerX500Principal.getName(X500Principal.RFC1779)
            useStrongBox = dn.contains(STRING_BOX)
        } else {
            attestationKeystoreAlias = persistentKeystoreAlias
            useStrongBox = isStrongBoxSupported(context)
        }
        val startTime = Date(Date().time - CLOCK_SKEW_MS)
        val builder = KeyGenParameterSpec.Builder(
            attestationKeystoreAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
            .setDigests(KEY_DIGEST)
            .setAttestationChallenge(challenge)
            .setKeyValidityStart(startTime)
        if (hasPersistentKey) {
            builder.setKeyValidityEnd(Date(startTime.time + EXPIRE_OFFSET_MS))
        }
        if (useStrongBox) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(useStrongBox)
            }
        }
        val generateKey = keyStoreProxy.generateKey(KeyProperties.KEY_ALGORITHM_EC, builder.build())
        val log = StringBuilder()
        if (!generateKey) {
            log.append("generate key fail")
            throw GeneralSecurityException(log.toString())
        }

        try {
            val fingerprint = keyStoreProxy.getCertificate(persistentKeystoreAlias)?.let {
                getFingerprint(
                    it
                )
            }
            if (fingerprint!!.size != FINGERPRINT_LENGTH) {
                log.append('\n').append("fingerprint length mismatch")
                //throw GeneralSecurityException(log.toString())
            }

            val attestationCertificates: Array<Certificate> = keyStoreProxy.getCertificateChain(
                attestationKeystoreAlias
            )
            verifyCertificateSignatures(attestationCertificates)

            val root0 = generateCertificate(context.resources, R.raw.google_root_0)
            val root1 = generateCertificate(context.resources, R.raw.google_root_1)
            val root2 = generateCertificate(context.resources, R.raw.google_root_2)
            /*log.append('\n').append("Google Root1:")
                .append(BaseEncoding.base16().encode(root1.encoded))
            log.append('\n').append("Google Root2:")
                .append(BaseEncoding.base16().encode(root2.encoded))*/


            // check that the root certificate is the Google key attestation root
            val attestationCertificate =
                attestationCertificates[attestationCertificates.size - 1] as X509Certificate

            log.append('\n').append("Attestation Root:")
                .append(BaseEncoding.base64().encode(attestationCertificate.encoded))


            if (!Arrays.equals(root0.encoded, attestationCertificate.encoded) &&
                !Arrays.equals(root1.encoded, attestationCertificate.encoded) &&
                !Arrays.equals(root2.encoded, attestationCertificate.encoded)
            ) {
                log.append('\n').append("root certificate is not a valid key attestation root")
                //throw GeneralSecurityException(log.toString())
            }

            val attestation = Attestation(attestationCertificates[0] as X509Certificate)
            val attestationSecurityLevel = attestation.attestationSecurityLevel
            log.append('\n').append("attestationSecurityLevel:$attestationSecurityLevel")
            // enforce hardware-based attestation
            if (attestationSecurityLevel != Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT &&
                attestationSecurityLevel != Attestation.KM_SECURITY_LEVEL_STRONG_BOX
            ) {
                log.append('\n').append("\"attestation security level is not valid\"")
                //throw GeneralSecurityException(log.toString())
            }

            val keymasterSecurityLevel = attestation.keymasterSecurityLevel
            log.append('\n').append("keymasterSecurityLevel:$keymasterSecurityLevel")
            if (keymasterSecurityLevel != attestationSecurityLevel) {
                log.append('\n')
                    .append("keymaster security level does not match attestation security level")
                //throw GeneralSecurityException(log.toString())
            }
            // prevent replay attacks
            if (!Arrays.equals(attestation.attestationChallenge, challenge)) {
                log.append('\n').append("challenge mismatch")
                //throw GeneralSecurityException(log.toString())
            }

            // enforce communicating with the attestation app via OS level security
            val softwareEnforced = attestation.softwareEnforced
            val attestationApplicationId = softwareEnforced.attestationApplicationId
            val signatureDigests = attestationApplicationId.signatureDigests
            log.append('\n').append("signatureDigests.size:${signatureDigests.size}")
            if (signatureDigests.size != 1) {
                log.append('\n').append("wrong number of attestation app signature digests")
                //throw GeneralSecurityException(log.toString())
            }

            val teeEnforced = attestation.teeEnforced
            // verified boot security checks
            val rootOfTrust = teeEnforced.rootOfTrust
            if (rootOfTrust == null) {
                log.append('\n').append("missing root of trust")
                throw GeneralSecurityException(log.toString())
            }

            if (!rootOfTrust.isDeviceLocked) {
                log.append('\n').append("device is not locked")
                //throw GeneralSecurityException(log.toString())
            }


            val verifiedBootState = rootOfTrust.verifiedBootState
            log.append('\n').append("verifiedBootState:$verifiedBootState")
            val verifiedBootKey = BaseEncoding.base16().encode(rootOfTrust.verifiedBootKey)
            val device: DeviceInfo? =
                if (verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED) {
                    if (attestationSecurityLevel == Attestation.KM_SECURITY_LEVEL_STRONG_BOX) {
                        log.append('\n').append("fingerprintsStrongBoxCustomOS")
                        fingerprintsStrongBoxCustomOS[verifiedBootKey]
                    } else {
                        log.append('\n').append("fingerprintsCustomOS")
                        fingerprintsCustomOS[verifiedBootKey]
                    }
                } else if (verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_VERIFIED) {
                    if (attestationSecurityLevel == Attestation.KM_SECURITY_LEVEL_STRONG_BOX) {
                        log.append('\n').append("fingerprintsStrongBoxStock")
                        fingerprintsStrongBoxStock[verifiedBootKey]
                    } else {
                        log.append('\n').append("fingerprintsStock")
                        fingerprintsStock[verifiedBootKey]
                    }
                } else {
                    log.append('\n').append("verified boot state is not verified or self signed")
                    throw GeneralSecurityException(log.toString())
                }

            if (device == null) {
                log.append('\n').append("invalid verified boot key fingerprint: $verifiedBootKey")
                throw GeneralSecurityException(log.toString())
            }


            // OS version sanity checks
            val osVersion = teeEnforced.osVersion
            if (osVersion == DEVELOPER_PREVIEW_OS_VERSION) {
                log.append('\n').append("OS version is not a production release")
                //throw GeneralSecurityException(log.toString())
            } else if (osVersion < OS_VERSION_MINIMUM) {
                log.append('\n').append("OS version too old: $osVersion")
                //throw GeneralSecurityException(log.toString())
            }

            val osPatchLevel = teeEnforced.osPatchLevel
            if (osPatchLevel < OS_PATCH_LEVEL_MINIMUM) {
                log.append('\n').append("OS patch level too old: $osPatchLevel")
                //throw GeneralSecurityException(log.toString())
            }

            val vendorPatchLevel = teeEnforced.vendorPatchLevel
            if (vendorPatchLevel != null) {
                if (vendorPatchLevel < VENDOR_PATCH_LEVEL_MINIMUM && !extraPatchLevelMissing.contains(
                        device.name
                    )
                ) {
                    log.append('\n').append("Vendor patch level too old: $vendorPatchLevel")
                    //throw GeneralSecurityException(log.toString())
                }
            }

            val bootPatchLevel = teeEnforced.bootPatchLevel
            if (bootPatchLevel != null) {
                if (bootPatchLevel < BOOT_PATCH_LEVEL_MINIMUM && !extraPatchLevelMissing.contains(
                        device.name
                    )
                ) {
                    log.append('\n').append("Boot patch level too old: $bootPatchLevel")
                    //throw GeneralSecurityException(log.toString())
                }
            }

            // key sanity checks
            if (teeEnforced.origin != AuthorizationList.KM_ORIGIN_GENERATED) {
                log.append('\n').append("not a generated key")
                //throw GeneralSecurityException(log.toString())
            }

            if (device.rollbackResistant && !teeEnforced.isRollbackResistant) {
                log.append('\n').append("expected rollback resistant key")
                //throw GeneralSecurityException(log.toString())
            }

            val attestationVersion = attestation.attestationVersion
            if (attestationVersion < device.attestationVersion) {
                log.append('\n')
                    .append("attestation version " + attestationVersion + " below " + device.attestationVersion)
                //throw GeneralSecurityException(log.toString())
            }
            val keymasterVersion = attestation.keymasterVersion
            if (keymasterVersion < device.keymasterVersion) {
                log.append('\n')
                    .append("keymaster version " + keymasterVersion + " below " + device.keymasterVersion)
                //throw GeneralSecurityException(log.toString())
            }

            val verifiedBootHash = rootOfTrust.verifiedBootHash
            if (attestationVersion >= 3 && verifiedBootHash == null) {
                log.append('\n').append("verifiedBootHash expected for attestation version >= 3")
                //throw GeneralSecurityException(log.toString())
            }

            // OS-enforced checks and information
            val dpm = context.getSystemService(DevicePolicyManager::class.java)

            val activeAdmins = dpm.activeAdmins
            if (activeAdmins != null) {
                for (name in activeAdmins) {
                    val pm = context.packageManager
                    try {
                        pm.getApplicationInfo(name.packageName, 0)
                    } catch (e: PackageManager.NameNotFoundException) {
                        log.append('\n').append(e.toString())
                        //throw GeneralSecurityException(log.toString())
                    }
                }
            }
            val encryptionStatus = dpm.storageEncryptionStatus
            log.append('\n').append("encryptionStatus:$encryptionStatus")
            log.append('\n').append("device.perUserEncryption:${device.perUserEncryption}")
            if (device.perUserEncryption) {
                if (encryptionStatus != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER) {
                    log.append('\n').append("invalid encryption status")
                    //throw GeneralSecurityException(log.toString())
                }
            } else {
                if (encryptionStatus != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE &&
                    encryptionStatus != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY
                ) {
                    log.append('\n').append("invalid encryption status")
                    //throw GeneralSecurityException(log.toString())
                }
            }

            val keyguardManager = context.getSystemService(KeyguardManager::class.java)
            val userProfileSecure = keyguardManager.isDeviceSecure
            log.append('\n').append("userProfileSecure:$userProfileSecure")
            if (userProfileSecure && !keyguardManager.isKeyguardSecure) {
                log.append('\n').append("keyguard state inconsistent")
                //throw GeneralSecurityException(log.toString())
            }
        } catch (e: GeneralSecurityException) {
            if (!hasPersistentKey) {
                keyStoreProxy.deleteKey(persistentKeystoreAlias)
            }
            log.append('\n').append(e.toString())
            throw e
        }
        return log.toString()
    }

    @Throws(GeneralSecurityException::class)
    private fun verifyCertificateSignatures(certChain: Array<Certificate>) {
        for (i in 1 until certChain.size) {
            val pubKey = certChain[i].publicKey
            try {
                // For now, rely on the random challenge to check validity of the attestation
                // certificate rather than the Not Before and Not After dates in the certificate.
                //
                // StrongBox implementations currently have issues with time sync and this doesn't
                // provide any additional security due to the challenge.
                if (i != 1) {
                    (certChain[i - 1] as X509Certificate).checkValidity()
                }
                certChain[i - 1].verify(pubKey)
            } catch (e: InvalidKeyException) {
                throw GeneralSecurityException(
                    "Failed to verify certificate "
                            + certChain[i - 1] + " with public key " + certChain[i].publicKey, e
                )
            } catch (e: CertificateException) {
                throw GeneralSecurityException(
                    ("Failed to verify certificate "
                            + certChain[i - 1] + " with public key " + certChain[i].publicKey), e
                )
            } catch (e: NoSuchAlgorithmException) {
                throw GeneralSecurityException(
                    ("Failed to verify certificate "
                            + certChain[i - 1] + " with public key " + certChain[i].publicKey), e
                )
            } catch (e: NoSuchProviderException) {
                throw GeneralSecurityException(
                    ("Failed to verify certificate "
                            + certChain[i - 1] + " with public key " + certChain[i].publicKey), e
                )
            } catch (e: SignatureException) {
                throw GeneralSecurityException(
                    ("Failed to verify certificate "
                            + certChain[i - 1] + " with public key " + certChain[i].publicKey), e
                )
            }
            if (i == certChain.size - 1) {
                // Last cert is self-signed.
                try {
                    (certChain[i] as X509Certificate).checkValidity()
                    certChain[i].verify(pubKey)
                } catch (e: CertificateException) {
                    throw GeneralSecurityException(
                        "Root cert " + certChain[i] + " is not correctly self-signed", e
                    )
                }
            }
        }
    }

    @Throws(CertificateException::class, IOException::class)
    private fun generateCertificate(resources: Resources, id: Int): X509Certificate {
        resources.openRawResource(id).use { stream ->
            return generateCertificate(stream)
        }
    }

    @Throws(CertificateException::class)
    private fun generateCertificate(`in`: InputStream): X509Certificate {
        return CertificateFactory.getInstance("X.509").generateCertificate(`in`) as X509Certificate
    }

    private fun getFingerprint(certificate: Certificate): ByteArray {
        return FINGERPRINT_HASH_FUNCTION.hashBytes(
            certificate.encoded
        ).asBytes()

    }

    private fun isStrongBoxSupported(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            IS_STRONGBOX_SUPPORTED
        }
    }

    private fun getChallengeIndex(context: Context): ByteArray {
        val global: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        val challengeIndexSerialized = global.getString(
            KEY_CHALLENGE_INDEX,
            null
        )
        return if (challengeIndexSerialized != null) {
            BaseEncoding.base64().decode(challengeIndexSerialized)
        } else {
            val challengeIndex: ByteArray = getChallenge()
            global.edit()
                .putString(
                    KEY_CHALLENGE_INDEX,
                    BaseEncoding.base64().encode(challengeIndex)
                )
                .apply()
            challengeIndex
        }
    }

    private fun getChallenge(): ByteArray {
        val random = SecureRandom()
        val challenge = ByteArray(CHALLENGE_LENGTH)
        random.nextBytes(challenge)
        return challenge
    }
}