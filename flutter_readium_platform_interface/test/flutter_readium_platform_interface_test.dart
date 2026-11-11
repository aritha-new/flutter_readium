import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_readium_platform_interface/method_channel_flutter_readium.dart';
import 'package:flutter_readium_platform_interface/src/index.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('$MethodChannelFlutterReadium', () {
    final log = <MethodCall>[];
    late MethodChannelFlutterReadium methodChannelReadium;
    final testTextLocator = Locator(
      href: 'chapter1.html',
      type: 'text/xhtml',
      locations: Locations(cssSelector: '#loc1'),
      text: LocatorText(before: 'a', highlight: 'b', after: 'c'),
    );
    const testExternalPlaybackCommand = ReadiumExternalPlaybackCommand(
      action: ExternalPlaybackCommandAction.seekTo,
      position: Duration(seconds: 42),
    );

    setUp(() async {
      methodChannelReadium = MethodChannelFlutterReadium();

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
        methodChannelReadium.methodChannel,
        (
          methodCall,
        ) async {
          log.add(methodCall);
          switch (methodCall.method) {
            case 'openProtectedPublication':
              return jsonEncode({
                'metadata': {'title': 'Protected fixture'},
                'links': <Object>[],
                'readingOrder': <Object>[],
              });
            case 'harivuDeviceProof':
              return jsonEncode({
                'devicePublicKey': 'public-key-b64url',
                'signature': 'signature-b64url',
                'keyProtection': 'hardware',
              });
            case 'harivuDeviceInfo':
              return jsonEncode({
                'devicePublicKey': 'public-key-b64url',
                'keyProtection': 'hardware',
                'attestationChain': ['leaf-cert-b64', 'root-cert-b64'],
              });
            case 'openPublication':
              return 'TODO';
            case 'ttsEnable':
              return true;
            case 'goForward':
              return true;
            default:
              return null;
          }
        },
      );
      log.clear();

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
        MethodChannel(methodChannelReadium.textLocatorChannel.name),
        (methodCall) async {
          switch (methodCall.method) {
            case 'listen':
              await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.handlePlatformMessage(
                methodChannelReadium.textLocatorChannel.name,
                methodChannelReadium.textLocatorChannel.codec.encodeSuccessEnvelope(
                  jsonEncode(testTextLocator.toJson()),
                ),
                (_) {},
              );
              break;
            case 'cancel':
            default:
              return null;
          }
          return null;
        },
      );

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
        MethodChannel(methodChannelReadium.externalPlaybackCommandChannel.name),
        (methodCall) async {
          switch (methodCall.method) {
            case 'listen':
              await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.handlePlatformMessage(
                methodChannelReadium.externalPlaybackCommandChannel.name,
                methodChannelReadium.externalPlaybackCommandChannel.codec.encodeSuccessEnvelope(
                  testExternalPlaybackCommand.toJson(),
                ),
                (_) {},
              );
              break;
            case 'cancel':
            default:
              return null;
          }
          return null;
        },
      );
    });

    test(
      'onTextLocatorChanged emits the locator sent from the platform',
      () async {
        final result = await methodChannelReadium.onTextLocatorChanged.first;
        expect(result, testTextLocator);
      },
    );

    test('setAudioRecoveryPolicy invokes the channel with a flat map (not json-encoded)', () async {
      const policy = AudioRecoveryPolicy(
        maxAttempts: 5,
        backoffBaseSeconds: 2.0,
        stallTimeoutSeconds: 15.0,
      );
      await methodChannelReadium.setAudioRecoveryPolicy(policy);
      expect(
        log,
        contains(
          isA<MethodCall>()
              .having((c) => c.method, 'method', 'setAudioRecoveryPolicy')
              .having((c) => c.arguments, 'arguments', policy.toJson()),
        ),
      );
    });

    test(
      'openProtectedPublication sends only the opaque publication identifier',
      () async {
        await methodChannelReadium.openProtectedPublication(
          'harivu-protected-fixture-v1',
        );

        expect(
          log,
          contains(
            isA<MethodCall>()
                .having(
                  (call) => call.method,
                  'method',
                  'openProtectedPublication',
                )
                .having(
                  (call) => call.arguments,
                  'arguments',
                  const ['harivu-protected-fixture-v1'],
                ),
          ),
        );
      },
    );

    test(
      'protectedDeviceProof sends only the message and returns the public key and signature',
      () async {
        final proof = await methodChannelReadium.protectedDeviceProof(
          'harivu-device-registration-v1|c|n|dk-1',
        );

        expect(proof.devicePublicKey, 'public-key-b64url');
        expect(proof.signature, 'signature-b64url');
        expect(proof.keyProtection, 'hardware');
        expect(
          log,
          contains(
            isA<MethodCall>().having((call) => call.method, 'method', 'harivuDeviceProof').having(
              (call) => call.arguments,
              'arguments',
              const ['harivu-device-registration-v1|c|n|dk-1'],
            ),
          ),
        );
      },
    );

    test(
      'protectedDeviceInfo asks native for the public key and protection level, sending nothing',
      () async {
        final info = await methodChannelReadium.protectedDeviceInfo();

        expect(info.devicePublicKey, 'public-key-b64url');
        expect(info.keyProtection, 'hardware');
        expect(
          log,
          contains(
            isA<MethodCall>().having((call) => call.method, 'method', 'harivuDeviceInfo'),
          ),
        );
      },
    );

    test('protectedDeviceInfo returns the attestation chain, leaf first', () async {
      final info = await methodChannelReadium.protectedDeviceInfo();

      expect(info.attestationChain, ['leaf-cert-b64', 'root-cert-b64']);
    });

    test('a device with nothing to attest has an empty attestation chain', () async {
      final proof = await methodChannelReadium.protectedDeviceProof('m');

      expect(proof.attestationChain, isEmpty);
      expect(
        const ProtectedDeviceInfo(devicePublicKey: 'k', keyProtection: 'software').attestationChain,
        isEmpty,
      );
    });

    test(
      'onExternalPlaybackCommand emits the command sent from the platform',
      () async {
        final result = await methodChannelReadium.onExternalPlaybackCommand.first;
        expect(result.action, testExternalPlaybackCommand.action);
        expect(result.position, testExternalPlaybackCommand.position);
      },
    );

    test('onExternalPlaybackCommand keeps its subscription across publication closes', () async {
      final stream = methodChannelReadium.onExternalPlaybackCommand;

      await methodChannelReadium.closePublication();

      expect(methodChannelReadium.onExternalPlaybackCommand, same(stream));
    });

    test('setPDFPreferences stores the preferences as the default for later readers', () async {
      const preferences = PDFPreferences(layout: PDFLayout.paginated);

      await methodChannelReadium.setPDFPreferences(preferences);

      expect(methodChannelReadium.defaultPDFPreferences?.toJson(), preferences.toJson());
    });

    test('setNarrationSyncEnabled invokes the channel with the bool argument', () async {
      await methodChannelReadium.setNarrationSyncEnabled(true);
      await methodChannelReadium.setNarrationSyncEnabled(false);
      expect(
        log,
        containsAllInOrder(<Matcher>[
          isA<MethodCall>()
              .having((c) => c.method, 'method', 'setNarrationSyncEnabled')
              .having((c) => c.arguments, 'arguments', true),
          isA<MethodCall>()
              .having((c) => c.method, 'method', 'setNarrationSyncEnabled')
              .having((c) => c.arguments, 'arguments', false),
        ]),
      );
    });
  });
}
