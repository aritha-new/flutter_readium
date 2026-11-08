import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('git dependencies include the native reader helper assets', () async {
    const helperAssets = <String>[
      'assets/helpers/flutterReadiumTools.js',
      'assets/helpers/flutterReadiumTools.css',
    ];

    for (final assetPath in helperAssets) {
      final tracked = await Process.run(
        'git',
        ['ls-files', '--error-unmatch', assetPath],
      );

      expect(
        tracked.exitCode,
        0,
        reason: '$assetPath must be tracked so Git dependencies receive it.',
      );
      expect(
        await File(assetPath).length(),
        greaterThan(0),
        reason: '$assetPath must contain the generated runtime helper.',
      );
    }
  });
}
