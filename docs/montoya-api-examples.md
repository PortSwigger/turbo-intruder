# Montoya API Examples and Patterns

## Basic Extension Structure

The main extension class implements `BurpExtension`:

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("My Extension");
        // Add your extension logic here
    }
}
```

## Common Extension Features

### Adding Context Menu Items
```java
montoyaApi.userInterface().registerContextMenuItemsProvider(contextMenuItemsProvider);
```

### Creating Custom Tabs
```java
montoyaApi.userInterface().registerSuiteTab(suiteTab);
```

### Adding Settings Panel
```java
SettingsPanelWithData panel = SettingsPanelBuilder.settingsPanel()
    .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
    .withTitle("Extension Settings")
    .withSettings(
        SettingsPanelSetting.stringSetting("API Key", ""),
        SettingsPanelSetting.booleanSetting("Enable Feature", true)
    )
    .build();

montoyaApi.userInterface().registerSettingsPanel(panel);
```

### Logging
```java
montoyaApi.logging().logToOutput("Extension loaded successfully");
montoyaApi.logging().logToError("Error occurred: " + errorMessage);
```

## AI-Powered Extensions

For AI-enhanced extensions, declare enhanced capabilities:

```java
@Override
public EnhancedCapability[] enhancedCapabilities() {
    return new EnhancedCapability[]{EnhancedCapability.AI_FEATURES};
}

@Override
public void initialize(MontoyaApi montoyaApi) {
    if (montoyaApi.ai().isEnabled()) {
        // AI functionality available
        AiService ai = montoyaApi.ai();
        
        // Example AI usage
        CompletableFuture<String> result = ai.generateResponse("Analyze this request");
        result.thenAccept(response -> {
            montoyaApi.logging().logToOutput("AI Response: " + response);
        });
    }
}
```