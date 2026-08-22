package world.w3b.kdbxfortress.ui.navigation

enum class TopLevelDestination(
    val route: String,
    val marker: String,
) {
    Vault(route = "vault", marker = "V"),
    Settings(route = "settings", marker = "S"),
}
