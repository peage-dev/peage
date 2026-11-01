package dev.peage.reactnative

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

class PeageAttestPackage : BaseReactPackage() {
    override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? =
        if (name == PeageAttestModule.NAME) PeageAttestModule(reactContext) else null

    override fun getReactModuleInfoProvider(): ReactModuleInfoProvider = ReactModuleInfoProvider {
        // Positional: React Native 0.76 names these parameters differently.
        mapOf(
            PeageAttestModule.NAME to ReactModuleInfo(
                PeageAttestModule.NAME,
                PeageAttestModule::class.java.name,
                false,
                false,
                false,
                true,
            ),
        )
    }
}
