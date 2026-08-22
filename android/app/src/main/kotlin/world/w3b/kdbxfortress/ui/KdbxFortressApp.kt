package world.w3b.kdbxfortress.ui

import android.text.InputType
import android.view.View
import android.widget.EditText
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import world.w3b.kdbxfortress.R
import world.w3b.kdbxfortress.bridge.NativeBridge
import world.w3b.kdbxfortress.ui.navigation.TopLevelDestination
import world.w3b.kdbxfortress.vault.VaultBrowserFailure
import world.w3b.kdbxfortress.vault.VaultBrowserState
import java.nio.CharBuffer

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KdbxFortressApp(
    nativeReady: Boolean,
    selectedDocumentName: String?,
    selectedDocumentPersistent: Boolean,
    selectedKeyFileName: String?,
    browserState: VaultBrowserState,
    onOpenVault: () -> Unit,
    onSelectKeyFile: () -> Unit,
    onClearKeyFile: () -> Unit,
    onUnlockVault: (ByteArray) -> Unit,
    onOpenGroup: (NativeBridge.MetadataId) -> Unit,
    onLockVault: () -> Unit,
    onCreateVault: () -> Unit,
    createVaultEnabled: Boolean,
    modifier: Modifier = Modifier,
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(title = { Text(text = stringResource(R.string.app_name)) })
        },
        bottomBar = {
            NavigationBar {
                TopLevelDestination.entries.forEach { destination ->
                    val selected = currentRoute == destination.route
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            navController.navigate(destination.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = {
                            Box(
                                modifier = Modifier.size(24.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(
                                    text = destination.marker,
                                    fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                )
                            }
                        },
                        label = { Text(text = destination.label()) },
                    )
                }
            }
        },
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = TopLevelDestination.Vault.route,
            modifier = Modifier.padding(innerPadding),
        ) {
            composable(TopLevelDestination.Vault.route) {
                VaultScreen(
                    nativeReady = nativeReady,
                    selectedDocumentName = selectedDocumentName,
                    selectedDocumentPersistent = selectedDocumentPersistent,
                    selectedKeyFileName = selectedKeyFileName,
                    browserState = browserState,
                    onOpenVault = onOpenVault,
                    onSelectKeyFile = onSelectKeyFile,
                    onClearKeyFile = onClearKeyFile,
                    onUnlockVault = onUnlockVault,
                    onOpenGroup = onOpenGroup,
                    onLockVault = onLockVault,
                    onCreateVault = onCreateVault,
                    createVaultEnabled = createVaultEnabled,
                )
            }
            composable(TopLevelDestination.Settings.route) {
                SettingsScreen()
            }
        }
    }
}

@Composable
private fun TopLevelDestination.label(): String = when (this) {
    TopLevelDestination.Vault -> stringResource(R.string.destination_vault)
    TopLevelDestination.Settings -> stringResource(R.string.destination_settings)
}

@Composable
private fun VaultScreen(
    nativeReady: Boolean,
    selectedDocumentName: String?,
    selectedDocumentPersistent: Boolean,
    selectedKeyFileName: String?,
    browserState: VaultBrowserState,
    onOpenVault: () -> Unit,
    onSelectKeyFile: () -> Unit,
    onClearKeyFile: () -> Unit,
    onUnlockVault: (ByteArray) -> Unit,
    onOpenGroup: (NativeBridge.MetadataId) -> Unit,
    onLockVault: () -> Unit,
    onCreateVault: () -> Unit,
    createVaultEnabled: Boolean,
) {
    when (browserState) {
        is VaultBrowserState.Open -> VaultBrowser(
            state = browserState,
            onOpenGroup = onOpenGroup,
            onLockVault = onLockVault,
        )

        else -> VaultUnlock(
            nativeReady = nativeReady,
            selectedDocumentName = selectedDocumentName,
            selectedDocumentPersistent = selectedDocumentPersistent,
            selectedKeyFileName = selectedKeyFileName,
            browserState = browserState,
            onOpenVault = onOpenVault,
            onSelectKeyFile = onSelectKeyFile,
            onClearKeyFile = onClearKeyFile,
            onUnlockVault = onUnlockVault,
            onCreateVault = onCreateVault,
            createVaultEnabled = createVaultEnabled,
        )
    }
}

@Composable
private fun VaultUnlock(
    nativeReady: Boolean,
    selectedDocumentName: String?,
    selectedDocumentPersistent: Boolean,
    selectedKeyFileName: String?,
    browserState: VaultBrowserState,
    onOpenVault: () -> Unit,
    onSelectKeyFile: () -> Unit,
    onClearKeyFile: () -> Unit,
    onUnlockVault: (ByteArray) -> Unit,
    onCreateVault: () -> Unit,
    createVaultEnabled: Boolean,
) {
    val passwordEditor = remember { mutableStateOf<EditText?>(null) }
    val loading = browserState is VaultBrowserState.Loading

    ScreenBody {
        Text(
            text = stringResource(
                if (selectedDocumentName == null) R.string.vault_empty_title else R.string.vault_unlock_title,
            ),
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            text = stringResource(R.string.vault_empty_body),
            style = MaterialTheme.typography.bodyLarge,
        )

        Button(onClick = onOpenVault, enabled = !loading) {
            Text(text = stringResource(R.string.vault_open_action))
        }

        selectedDocumentName?.let { name ->
            Text(
                text = stringResource(R.string.vault_selected_document, name),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = stringResource(
                    if (selectedDocumentPersistent) {
                        R.string.vault_document_access_persistent
                    } else {
                        R.string.vault_document_access_session
                    },
                ),
                style = MaterialTheme.typography.bodySmall,
                color = if (selectedDocumentPersistent) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.error
                },
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onSelectKeyFile, enabled = !loading) {
                    Text(text = stringResource(R.string.vault_keyfile_select_action))
                }
                if (selectedKeyFileName != null) {
                    TextButton(onClick = onClearKeyFile, enabled = !loading) {
                        Text(text = stringResource(R.string.vault_keyfile_clear_action))
                    }
                }
            }

            Text(
                text = selectedKeyFileName?.let {
                    stringResource(R.string.vault_keyfile_selected, it)
                } ?: stringResource(R.string.vault_keyfile_optional),
                style = MaterialTheme.typography.bodySmall,
            )

            AndroidView(
                modifier = Modifier.fillMaxWidth(),
                factory = { context ->
                    EditText(context).apply {
                        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                        hint = context.getString(R.string.vault_password_hint)
                        isSingleLine = true
                        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                        passwordEditor.value = this
                    }
                },
                update = { editor -> passwordEditor.value = editor },
            )

            Button(
                onClick = {
                    val password = passwordEditor.value?.consumeUtf8Bytes() ?: ByteArray(0)
                    onUnlockVault(password)
                },
                enabled = nativeReady && !loading,
            ) {
                Text(text = stringResource(R.string.vault_unlock_action))
            }
        }

        if (loading) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
                Text(text = stringResource(R.string.vault_unlock_progress))
            }
        }

        if (browserState is VaultBrowserState.Failure) {
            Text(
                text = browserState.reason.userMessage(),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        OutlinedButton(
            onClick = onCreateVault,
            enabled = createVaultEnabled && !loading,
        ) {
            Text(text = stringResource(R.string.vault_create_action))
        }

        if (!createVaultEnabled) {
            Text(
                text = stringResource(R.string.vault_create_pending),
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Text(
            text = stringResource(
                if (nativeReady) R.string.native_core_ready else R.string.native_core_unavailable,
            ),
            color = if (nativeReady) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.error
            },
            style = MaterialTheme.typography.labelLarge,
        )
    }
}

@Composable
private fun VaultBrowser(
    state: VaultBrowserState.Open,
    onOpenGroup: (NativeBridge.MetadataId) -> Unit,
    onLockVault: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = state.vault.databaseName ?: stringResource(R.string.vault_open_database_unnamed),
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            text = state.group.name.ifEmpty { stringResource(R.string.vault_root_group) },
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = stringResource(
                R.string.vault_browser_counts,
                state.childGroups.size,
                state.entries.size,
            ),
            style = MaterialTheme.typography.bodySmall,
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            state.group.parentId?.let { parentId ->
                OutlinedButton(onClick = { onOpenGroup(parentId) }) {
                    Text(text = stringResource(R.string.vault_group_up_action))
                }
            }
            OutlinedButton(onClick = onLockVault) {
                Text(text = stringResource(R.string.vault_lock_action))
            }
        }

        HorizontalDivider()

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(state.childGroups) { group ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { onOpenGroup(group.id) },
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = group.name.ifEmpty { stringResource(R.string.vault_group_unnamed) },
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(
                            text = stringResource(
                                R.string.vault_group_counts,
                                group.childGroupIds.size,
                                group.entryIds.size,
                            ),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }

            items(state.entries) { entry ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = entry.title ?: stringResource(R.string.vault_entry_title_hidden),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        entry.username?.takeIf(String::isNotEmpty)?.let { username ->
                            Text(text = username, style = MaterialTheme.typography.bodyMedium)
                        }
                        entry.url?.takeIf(String::isNotEmpty)?.let { url ->
                            Text(text = url, style = MaterialTheme.typography.bodySmall)
                        }
                        Text(
                            text = entry.metadataLabel(),
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                }
            }

            if (state.childGroups.isEmpty() && state.entries.isEmpty()) {
                item {
                    Text(
                        text = stringResource(R.string.vault_group_empty),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun NativeBridge.EntrySummary.metadataLabel(): String {
    val labels = mutableListOf<String>()
    if (hasPassword) labels += stringResource(R.string.vault_entry_has_password)
    if (hasOtp) labels += stringResource(R.string.vault_entry_has_otp)
    if (attachmentCount > 0L) {
        labels += stringResource(R.string.vault_entry_attachment_count, attachmentCount)
    }
    return if (labels.isEmpty()) {
        stringResource(R.string.vault_entry_metadata_only)
    } else {
        labels.joinToString(separator = " • ")
    }
}

@Composable
private fun VaultBrowserFailure.userMessage(): String = stringResource(
    when (this) {
        VaultBrowserFailure.VaultTooLarge -> R.string.vault_error_too_large
        VaultBrowserFailure.KeyFileTooLarge -> R.string.vault_error_keyfile_too_large
        VaultBrowserFailure.DocumentUnavailable -> R.string.vault_error_document_unavailable
        VaultBrowserFailure.DocumentReadFailed -> R.string.vault_error_document_read
        VaultBrowserFailure.CredentialTooLarge -> R.string.vault_error_credential_too_large
        VaultBrowserFailure.CredentialsRejected -> R.string.vault_error_credentials
        VaultBrowserFailure.UnsupportedFormat -> R.string.vault_error_unsupported
        VaultBrowserFailure.ResourceLimit -> R.string.vault_error_resource_limit
        VaultBrowserFailure.InvalidInput -> R.string.vault_error_invalid_input
        VaultBrowserFailure.CapacityExceeded -> R.string.vault_error_capacity
        VaultBrowserFailure.PageTooLarge -> R.string.vault_error_page_too_large
        VaultBrowserFailure.MetadataUnavailable -> R.string.vault_error_metadata
        VaultBrowserFailure.CoreFailure -> R.string.vault_error_core
    },
)

private fun EditText.consumeUtf8Bytes(): ByteArray {
    val editable = text ?: return ByteArray(0)
    val chars = CharArray(editable.length)
    for (index in chars.indices) {
        chars[index] = editable[index]
    }
    editable.clear()

    val encoded = Charsets.UTF_8.encode(CharBuffer.wrap(chars))
    return try {
        val result = ByteArray(encoded.remaining())
        encoded.get(result)
        result
    } finally {
        chars.fill('\u0000')
        if (encoded.hasArray()) encoded.array().fill(0)
    }
}

@Composable
private fun SettingsScreen() {
    ScreenBody {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            text = stringResource(R.string.settings_body),
            style = MaterialTheme.typography.bodyLarge,
        )
    }
}

@Composable
private fun ScreenBody(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(PaddingValues(horizontal = 24.dp, vertical = 32.dp)),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.Start,
    ) {
        content()
    }
}
