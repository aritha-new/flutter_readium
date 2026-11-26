import '../index.dart';

abstract class ReadiumReaderWidgetInterface {
  /// Call to navigate the reader to a location.
  Future<void> go(
    final Locator locator, {
    required final bool isAudioBookWithText,
    final bool animated = false,
  });

  /// Go to previous page.
  Future<void> goBackward({final bool animated = true});

  /// Go to next page.
  Future<void> goForward({final bool animated = true});

  /// Set EPUB preferences
  Future<void> setEPUBPreferences(EPUBPreferences preferences);

  /// Set PDF preferences
  Future<void> setPDFPreferences(PDFPreferences preferences);

  /// Apply decorations
  Future<void> applyDecorations(String id, List<ReaderDecoration> decorations);

  /// Hides the text selection and its handles. Android draws the selection
  /// handles in their own windows above all Flutter widgets, so a Flutter
  /// dialog can't cover them. Returns where the selection was, to pass to
  /// [restoreSelection], or null when nothing was selected. Keep it yourself:
  /// the page may be reloaded meanwhile (e.g. while the app is in the
  /// background).
  Future<String?> hideSelection();

  /// Selects again the text [hideSelection] described in [saved]. Android
  /// shows handles only for selections made by touch, so the text comes back
  /// selected without them. Returns false when it couldn't be selected.
  Future<bool> restoreSelection(String saved);
}
