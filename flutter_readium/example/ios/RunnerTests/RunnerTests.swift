import CryptoKit
import XCTest
import ReadiumNavigator
import ReadiumShared

@testable import flutter_readium

// All native iOS unit tests live in this app-hosted RunnerTests directory, because the plugin's
// `import Flutter` module is only resolvable inside the app host, not under plain `swift test`.
// A new test file must be registered in the RunnerTests target of Runner.xcodeproj; bin/unit_tests
// fails if one is missing. See bin/unit_tests for the rationale.

// Regression tests for media-overlay item range matching.
class FlutterMediaOverlayItemTests: XCTestCase {
  private func makeItem(audio: String) -> FlutterMediaOverlayItem {
    FlutterMediaOverlayItem(audio: audio, text: "ch1.html#p1", position: 0)
  }

  // Regression: a reversed `t=start,end` fragment (end < start) used to trap
  // `start...end` with "Range requires lowerBound <= upperBound".
  func testIsAudioInRangeOfTimeDoesNotTrapOnReversedFragment() {
    let item = makeItem(audio: "ch1.mp3#t=10,5")

    // Degrades to the open-ended rule (time >= start): 7 < 10 → false, no crash.
    XCTAssertFalse(item.isAudioInRangeOfTime(7, inHref: "ch1.mp3"))
    // time >= start still selects the item.
    XCTAssertTrue(item.isAudioInRangeOfTime(12, inHref: "ch1.mp3"))
  }

  // Regression: a non-finite bound (Double("nan") parses successfully) must not trap.
  func testIsAudioInRangeOfTimeDoesNotTrapOnNaNFragment() {
    let item = makeItem(audio: "ch1.mp3#t=nan,5")

    XCTAssertFalse(item.isAudioInRangeOfTime(3, inHref: "ch1.mp3"))
  }

  // Happy path unchanged: well-formed range still matches by containment.
  func testIsAudioInRangeOfTimeMatchesWellFormedRange() {
    let item = makeItem(audio: "ch1.mp3#t=5,10")

    XCTAssertFalse(item.isAudioInRangeOfTime(4, inHref: "ch1.mp3"))
    XCTAssertTrue(item.isAudioInRangeOfTime(5, inHref: "ch1.mp3"))
    XCTAssertTrue(item.isAudioInRangeOfTime(9.999, inHref: "ch1.mp3"))
    XCTAssertFalse(item.isAudioInRangeOfTime(10, inHref: "ch1.mp3"))
    XCTAssertFalse(item.isAudioInRangeOfTime(11, inHref: "ch1.mp3"))
  }

  // Open-ended item (start only, no end) matches any time at or after start.
  func testIsAudioInRangeOfTimeOpenEndedFromStart() {
    let item = makeItem(audio: "ch1.mp3#t=5")

    XCTAssertFalse(item.isAudioInRangeOfTime(4, inHref: "ch1.mp3"))
    XCTAssertTrue(item.isAudioInRangeOfTime(5, inHref: "ch1.mp3"))
    XCTAssertTrue(item.isAudioInRangeOfTime(999, inHref: "ch1.mp3"))
  }

  // Non-matching href short-circuits regardless of fragment.
  func testIsAudioInRangeOfTimeRejectsUnknownHref() {
    let item = makeItem(audio: "ch1.mp3#t=5,10")

    XCTAssertFalse(item.isAudioInRangeOfTime(7, inHref: "other.mp3"))
  }
}

final class AudioStreamErrorPolicyTests: XCTestCase {
  private func httpResponse(status: Int) -> HTTPResponse {
    let url = HTTPURL(string: "https://example.com/audio.mp3")!
    return HTTPResponse(
      request: HTTPRequest(url: url),
      url: url,
      status: HTTPStatus(rawValue: status),
      headers: [:],
      mediaType: nil,
      body: nil
    )
  }

  func testCancelledIsIgnored() {
    XCTAssertEqual(ReadError.cancelled.audioStreamAction, .ignore)
  }

  func testHttpCancelledIsIgnored() {
    XCTAssertEqual(ReadError.access(.http(.cancelled)).audioStreamAction, .ignore)
  }

  func testTimeoutOfflineUnreachableAreRetryable() {
    XCTAssertEqual(ReadError.access(.http(.timeout(nil))).audioStreamAction, .retry)
    XCTAssertEqual(ReadError.access(.http(.offline(nil))).audioStreamAction, .retry)
    XCTAssertEqual(ReadError.access(.http(.unreachable(nil))).audioStreamAction, .retry)
  }

  func testRangeNotSupportedIsTerminalWithRangeNotSupportedReason() {
    XCTAssertEqual(
      ReadError.access(.http(.rangeNotSupported)).audioStreamAction,
      .fail(code: "AudioStreamError", reason: .rangeNotSupported))
  }

  func testAuthErrorsAreTerminalWithAuthCode() {
    XCTAssertEqual(
      ReadError.access(.http(.errorResponse(httpResponse(status: 401)))).audioStreamAction,
      .fail(code: "AudioStreamAuthError"))
    XCTAssertEqual(
      ReadError.access(.http(.errorResponse(httpResponse(status: 403)))).audioStreamAction,
      .fail(code: "AudioStreamAuthError"))
  }

  func testServerErrorsAreRetryableClientErrorsAreNot() {
    XCTAssertEqual(
      ReadError.access(.http(.errorResponse(httpResponse(status: 503)))).audioStreamAction,
      .retry)
    XCTAssertEqual(
      ReadError.access(.http(.errorResponse(httpResponse(status: 404)))).audioStreamAction,
      .fail(code: "AudioStreamHTTPError"))
  }

  func testDecodingErrorIsTerminal() {
    XCTAssertEqual(
      ReadError.decoding("bad data").audioStreamAction,
      .fail(code: "AudioStreamError"))
  }

  func testHttpStatusExtractsStatusFromErrorResponse() {
    XCTAssertEqual(
      ReadError.access(.http(.errorResponse(httpResponse(status: 401)))).httpStatus, 401)
    XCTAssertEqual(
      ReadError.access(.http(.errorResponse(httpResponse(status: 503)))).httpStatus, 503)
  }

  func testHttpStatusIsNilForNonErrorResponseCases() {
    XCTAssertNil(ReadError.access(.http(.timeout(nil))).httpStatus)
    XCTAssertNil(ReadError.access(.http(.offline(nil))).httpStatus)
    XCTAssertNil(ReadError.cancelled.httpStatus)
    XCTAssertNil(ReadError.decoding("bad data").httpStatus)
  }
}

final class AudioPlaybackStateMappingTests: XCTestCase {
  func testPlayingAtZeroWithPlaybackIntentMapsToLoading() {
    let info = MediaPlaybackInfo(resourceIndex: 0, state: .playing, time: 0, duration: 10)

    XCTAssertEqual(info.asClientTimebasedState(playbackIntent: true), .loading)
  }

  func testPlayingAtZeroWithoutPlaybackIntentStaysPlaying() {
    let info = MediaPlaybackInfo(resourceIndex: 0, state: .playing, time: 0, duration: 10)

    XCTAssertEqual(info.asClientTimebasedState(playbackIntent: false), .playing)
  }

  func testPlayingAfterProgressStaysPlaying() {
    let info = MediaPlaybackInfo(resourceIndex: 0, state: .playing, time: 0.01, duration: 10)

    XCTAssertEqual(info.asClientTimebasedState(playbackIntent: true), .playing)
  }

  func testNonPlayingStatesPassThrough() {
    XCTAssertEqual(
      MediaPlaybackInfo(resourceIndex: 0, state: .loading, time: 0, duration: 10)
        .asClientTimebasedState(playbackIntent: true),
      .loading)
    XCTAssertEqual(
      MediaPlaybackInfo(resourceIndex: 0, state: .paused, time: 0, duration: 10)
        .asClientTimebasedState(playbackIntent: true),
      .paused)
  }
}

final class FlutterReadiumErrorTests: XCTestCase {
  private func decodedJSON(_ jsonString: String) -> [String: Any] {
    let data = jsonString.data(using: .utf8)!
    return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
  }

  func testSerializesStructuredDataObject() {
    let error = FlutterReadiumError(
      message: "boom", code: "AudioStreamRetry",
      data: ["href": "ch1.mp3", "attempt": 1, "maxAttempts": 3])
    let json = decodedJSON(error.toJsonString())

    XCTAssertEqual(json["message"] as? String, "boom")
    XCTAssertEqual(json["code"] as? String, "AudioStreamRetry")
    let data = json["data"] as? [String: Any]
    XCTAssertEqual(data?["href"] as? String, "ch1.mp3")
    XCTAssertEqual(data?["attempt"] as? Int, 1)
    XCTAssertEqual(data?["maxAttempts"] as? Int, 3)
  }

  func testOmitsDataKeyWhenNilOrEmpty() {
    XCTAssertNil(decodedJSON(FlutterReadiumError(message: "boom", code: "X", data: nil).toJsonString())["data"])
    XCTAssertNil(decodedJSON(FlutterReadiumError(message: "boom", code: "X", data: [:]).toJsonString())["data"])
  }

  func testToFlutterErrorPreservesCodeMessageAndStructuredDetails() {
    let flutterError = FlutterReadiumError(
      message: "boom",
      code: "notFound",
      data: ["message": "missing", "httpStatus": 404]
    ).toFlutterError()

    XCTAssertEqual(flutterError.code, "notFound")
    XCTAssertEqual(flutterError.message, "boom")
    let details = flutterError.details as? [String: Any]
    XCTAssertEqual(details?["message"] as? String, "missing")
    XCTAssertEqual(details?["httpStatus"] as? Int, 404)
  }

  func testVoiceNotFoundFlutterErrorUsesVoiceNotFoundCode() {
    let flutterError = ReadiumError.voiceNotFound.toFlutterError()

    XCTAssertEqual(flutterError.code, "voiceNotFound")
  }
}

final class AudioRecoveryPolicyTests: XCTestCase {
  func testExponentialBackoffDelays() {
    let policy = AudioRecoveryPolicy()
    XCTAssertEqual(policy.maxAttempts, 3)
    XCTAssertFalse(policy.recoverOnResourceLoadingTimeout)
    XCTAssertEqual(policy.delay(forAttempt: 1), 1.0)
    XCTAssertEqual(policy.delay(forAttempt: 2), 2.0)
    XCTAssertEqual(policy.delay(forAttempt: 3), 4.0)
  }

  func testLoadingTimeoutRecoveryOptInParsesAndInvalidValueDefaultsFalse() {
    XCTAssertTrue(AudioRecoveryPolicy.fromMap(["recoverOnResourceLoadingTimeout": true]).recoverOnResourceLoadingTimeout)
    XCTAssertFalse(AudioRecoveryPolicy.fromMap(["recoverOnResourceLoadingTimeout": "true"]).recoverOnResourceLoadingTimeout)
  }
}

final class AudioResourceLoadingWatchdogTests: XCTestCase {
  func testWatchesExactlyWhilePlaybackIsIntended() {
    XCTAssertFalse(shouldWatchForResourceLoading(playbackIntent: false))
    XCTAssertTrue(shouldWatchForResourceLoading(playbackIntent: true))
    XCTAssertFalse(shouldWatchForResourceLoading(playbackIntent: true, isInterrupted: true))
  }

  func testFrozenPositionReportsOnceAtDeadline() {
    var watchdog = AudioResourceLoadingWatchdog()

    watchdog.arm(resourceIndex: 0, time: 10, now: 0, timeout: 3)
    XCTAssertFalse(watchdog.observe(resourceIndex: 0, time: 10, now: 2.99, timeout: 3))
    XCTAssertTrue(watchdog.observe(resourceIndex: 0, time: 10, now: 3, timeout: 3))
    XCTAssertFalse(watchdog.observe(resourceIndex: 0, time: 10, now: 6, timeout: 3))
  }

  func testForwardProgressPermanentlyDisarmsResource() {
    var watchdog = AudioResourceLoadingWatchdog()

    watchdog.arm(resourceIndex: 0, time: 10, now: 0, timeout: 3)
    XCTAssertFalse(watchdog.observe(resourceIndex: 0, time: 10.2, now: 2, timeout: 3))
    XCTAssertFalse(watchdog.observe(resourceIndex: 0, time: 10.2, now: 50, timeout: 3))
  }

  func testBackwardMovementDoesNotCountAsProgress() {
    var watchdog = AudioResourceLoadingWatchdog()

    watchdog.arm(resourceIndex: 0, time: 10, now: 0, timeout: 3)
    XCTAssertFalse(watchdog.observe(resourceIndex: 0, time: 2, now: 2, timeout: 3))
    XCTAssertTrue(watchdog.observe(resourceIndex: 0, time: 2, now: 3, timeout: 3))
  }

  func testResourceChangeStartsFreshWindowAfterProgress() {
    var watchdog = AudioResourceLoadingWatchdog()

    watchdog.arm(resourceIndex: 0, time: 10, now: 0, timeout: 3)
    XCTAssertFalse(watchdog.observe(resourceIndex: 0, time: 10.2, now: 1, timeout: 3))
    XCTAssertFalse(watchdog.observe(resourceIndex: 1, time: 0, now: 2, timeout: 3))
    XCTAssertTrue(watchdog.observe(resourceIndex: 1, time: 0, now: 5, timeout: 3))
  }

  func testResetStartsFreshWindow() {
    var watchdog = AudioResourceLoadingWatchdog()

    watchdog.arm(resourceIndex: 0, time: 10, now: 0, timeout: 3)
    watchdog.reset(resourceIndex: 0)
    watchdog.arm(resourceIndex: 0, time: 10, now: 10, timeout: 3)
    XCTAssertFalse(watchdog.observe(resourceIndex: 0, time: 10, now: 12, timeout: 3))
  }
}

/// Resource stub whose reads always fail with the given error.
private final class FailingResource: Resource {
  let error: ReadError
  init(error: ReadError) { self.error = error }
  var sourceURL: AbsoluteURL? { nil }
  func properties() async -> ReadResult<ResourceProperties> { .failure(error) }
  func estimatedLength() async -> ReadResult<UInt64?> { .failure(error) }
  func stream(range: Range<UInt64>?, consume: @escaping (Data) -> Void) async -> ReadResult<Void> {
    .failure(error)
  }
}

private struct SingleResourceContainer: Container {
  let href: AnyURL
  let resource: Resource
  var sourceURL: AbsoluteURL? { nil }
  var entries: Set<AnyURL> { [href] }
  subscript(url: any URLConvertible) -> Resource? {
    url.anyURL.normalized == href ? resource : nil
  }
}

final class ResourceReadErrorReportingTests: XCTestCase {
  func testStreamFailureIsReportedWithHref() async {
    let href = AnyURL(string: "https://example.com/ch1.mp3")!
    let observer = ResourceReadErrorObserver()
    var reported: (AnyURL, ReadError)?
    observer.setHandler { reported = ($0, $1) }

    let container = ReadErrorReportingContainer(
      wrapping: SingleResourceContainer(href: href, resource: FailingResource(error: .access(.http(.timeout(nil))))),
      observer: observer)

    let result = await container[href]!.stream(range: nil, consume: { _ in })

    guard case .failure = result else { return XCTFail("expected failure passthrough") }
    XCTAssertEqual(reported?.0, href)
    if case .access(.http(.timeout)) = reported?.1 {} else { XCTFail("wrong error: \(String(describing: reported?.1))") }
  }

  func testPropertiesFailuresAreNotReported() async {
    let href = AnyURL(string: "https://example.com/ch1.mp3")!
    let observer = ResourceReadErrorObserver()
    var reportCount = 0
    observer.setHandler { _, _ in reportCount += 1 }

    let container = ReadErrorReportingContainer(
      wrapping: SingleResourceContainer(href: href, resource: FailingResource(error: .access(.other(DebugError("probe failed"))))),
      observer: observer)

    guard case .failure = await container[href]!.properties() else {
      return XCTFail("expected properties failure passthrough")
    }

    XCTAssertEqual(reportCount, 0)
  }

  func testEstimatedLengthFailureIsReportedWithHref() async {
    let href = AnyURL(string: "https://example.com/ch1.mp3")!
    let observer = ResourceReadErrorObserver()
    var reported: (AnyURL, ReadError)?
    observer.setHandler { reported = ($0, $1) }

    let container = ReadErrorReportingContainer(
      wrapping: SingleResourceContainer(href: href, resource: FailingResource(error: .access(.http(.offline(nil))))),
      observer: observer)

    guard case .failure = await container[href]!.estimatedLength() else {
      return XCTFail("expected estimatedLength failure passthrough")
    }

    XCTAssertEqual(reported?.0, href)
    if case .access(.http(.offline)) = reported?.1 {} else { XCTFail("wrong error: \(String(describing: reported?.1))") }
  }

  func testSuccessIsNotReported() async {
    let href = AnyURL(string: "https://example.com/ch1.mp3")!
    let observer = ResourceReadErrorObserver()
    var reportCount = 0
    observer.setHandler { _, _ in reportCount += 1 }

    let container = ReadErrorReportingContainer(
      wrapping: SingleResourceContainer(href: href, resource: DataResource(data: Data([1, 2, 3]))),
      observer: observer)

    _ = await container[href]!.read()
    XCTAssertEqual(reportCount, 0)
  }
}

// Bounds an operation that ignores cancellation, verifying withTimeout resolves to
// nil rather than hanging forever. See FlutterAudioNavigator.goBounded(to:).
final class WithTimeoutTests: XCTestCase {
  func testWithTimeoutReturnsNilForOperationThatIgnoresCancellation() async {
    let result: Void? = await withTimeout(seconds: 1) {
      // Never resumes and ignores cancellation, without spinning after the timeout fires.
      await withUnsafeContinuation { (_: UnsafeContinuation<Void, Never>) in }
    }

    XCTAssertNil(result)
  }
}

// Regression: the Text-based initial locator must map to an Audio locator once the media-overlays
// are loaded. Mapping it in `init` always failed, as `mediaOverlays` is empty until `initNavigator`.
@MainActor
final class FlutterMediaOverlayNavigatorInitialLocatorTests: XCTestCase {
  private let overlays = [
    FlutterMediaOverlay(
      items: [
        FlutterMediaOverlayItem(audio: "chap1.mp3#t=0,5", text: "chap1.xhtml#p1", position: 0),
        FlutterMediaOverlayItem(audio: "chap1.mp3#t=5,10", text: "chap1.xhtml#p2", position: 0),
      ],
      readingOrderDuration: nil),
    FlutterMediaOverlay(
      items: [
        FlutterMediaOverlayItem(audio: "chap2.mp3#t=0,3", text: "chap2.xhtml#q1", position: 1),
        FlutterMediaOverlayItem(audio: "chap2.mp3#t=3,8", text: "chap2.xhtml#q2", position: 1),
      ],
      readingOrderDuration: nil),
  ]

  private func makeNavigator(initialLocator: Locator?) -> FlutterMediaOverlayNavigator {
    let publication = Publication(manifest: Manifest(
      metadata: Metadata(title: "Narrated"),
      readingOrder: [
        Link(href: "chap1.xhtml", mediaType: .xhtml),
        Link(href: "chap2.xhtml", mediaType: .xhtml),
      ]))
    return FlutterMediaOverlayNavigator(
      publication: publication,
      preferences: FlutterAudioPreferences(),
      initialLocator: initialLocator)
  }

  func testInitialTextLocatorMapsToAudioLocatorOnceOverlaysAreLoaded() throws {
    let navigator = makeNavigator(initialLocator: Locator(
      href: URL(string: "chap2.xhtml")!,
      mediaType: .xhtml,
      locations: .init(fragments: ["#q2"])))

    navigator.applyMediaOverlays(overlays)

    let audio = try XCTUnwrap(navigator.initialLocator, "initialLocator was not mapped to an audio locator")
    XCTAssertEqual(audio.href.string, "chap2.mp3")
    XCTAssertEqual(audio.timeOffset, 3)
  }

  // A saved combined locator (text id + audio time) must keep its more precise time.
  func testInitialCombinedLocatorKeepsItsTimeOffset() throws {
    let navigator = makeNavigator(initialLocator: Locator(
      href: URL(string: "chap2.xhtml")!,
      mediaType: .xhtml,
      locations: .init(fragments: ["#q2", "t=5.5"])))

    navigator.applyMediaOverlays(overlays)

    let audio = try XCTUnwrap(navigator.initialLocator, "initialLocator was not mapped to an audio locator")
    XCTAssertEqual(audio.href.string, "chap2.mp3")
    XCTAssertEqual(audio.timeOffset, 5.5)
  }
}

final class GuidedNavigationDetectionTests: XCTestCase {
  private let audio = Link(href: "chapter1.mp3", mediaType: .mp3)

  private func guidedNavigationEbook(alternates: [Link] = [], resources: [Link] = []) -> Publication {
    Publication(manifest: Manifest(
      metadata: Metadata(conformsTo: [.epub], title: "Guided navigation publication"),
      links: [Link(href: "guided-navigation.json", mediaType: MediaType("application/guided-navigation+json")!)],
      readingOrder: [Link(href: "chapter1.xhtml", mediaType: .xhtml, alternates: alternates)],
      resources: resources))
  }

  func testGuidedNavigationLinkWithAudioResourcesIsDetected() {
    let publication = guidedNavigationEbook(resources: [audio])

    XCTAssertTrue(publication.containsGuidedNavigationMediaOverlays)
  }

  func testGuidedNavigationLinkWithAudioAlternateIsDetected() {
    let publication = guidedNavigationEbook(alternates: [audio])

    XCTAssertTrue(publication.containsGuidedNavigationMediaOverlays)
  }

  func testGuidedNavigationLinkWithoutAudioResourcesIsIgnored() {
    let publication = guidedNavigationEbook(resources: [Link(href: "page01.jpg", mediaType: .jpeg)])

    XCTAssertFalse(publication.containsGuidedNavigationMediaOverlays)
  }
}


// Harivu protected-publication vectors (shared with Kotlin: test_vectors/harivu_protection_v1.json).
final class HarivuProtectionTests: XCTestCase {
  private let manifest = Data(#"{"algorithm":"A256GCM","format":"harivu-protected-epub","maxPlaintextResourceSize":2097152,"packageVersion":1,"publicationId":"harivu-phase2-fixture","publicationVersion":1,"resources":[{"ciphertextSha256":"a80cb620da0e4fdb4bc92fe6502d642244c2a6d9c8c9927ca29166363f51e2fa","mediaType":"application/xhtml+xml","nonce":"AAECAwQFBgcICQoL","path":"EPUB/chapter-1.xhtml","plaintextLength":33,"plaintextSha256":"47dff6bbaad22345246b1bda8749fa5c8d2a16ed5e0063f1c56ec42716dee73e","tag":"7nBsYxQ55IbLxHEXfH8kMw"}]}"#.utf8)
  private let license = #"eyJhbGciOiJFUzI1NiIsImtpZCI6Imhhcml2dS1kZXYtc2lnbmluZy1rZXktdjEiLCJ0eXAiOiJoYXJpdnUtbGljZW5zZStqd3MifQ.eyJjb250ZW50S2V5V3JhcCI6eyJhbGdvcml0aG0iOiJFQ0RILUVTK0hLREYtU0hBMjU2K0EyNTZHQ00iLCJlcGhlbWVyYWxQdWJsaWNLZXkiOiJCTVpWblVGdC0xYXZjVThVYlpGOEpLdjRHTEw3RWhZRUVwWkpoSUl3b3RKWXNxYllMY2JHYzB6d2t2LXFuOEFTOFE5d0NOT1ZLZ2pWZVg2Rl9xdWwyWGMiLCJub25jZSI6IkRBME9EeEFSRWhNVUZSWVgiLCJ0YWciOiJWckRYTHFxdHFlbVdMZ1VJcHpIVEZnIiwid3JhcHBlZENvbnRlbnRLZXkiOiJ1OXZpeGdpOV9xRmxfaWY3YUxVcEFsaUVwcTdqVllZamNnYk14bHZ1eVI4In0sImRldmljZUlkIjoiaGFyaXZ1LWRldi1kZXZpY2UtdjEiLCJkZXZpY2VLZXlJZCI6Imhhcml2dS1kZXYtZGV2aWNlLWtleS12MSIsImV4cGlyZXNBdCI6IjIwMzYtMDEtMDFUMDA6MDA6MDBaIiwiZm9ybWF0IjoiaGFyaXZ1LW9mZmxpbmUtbGljZW5zZSIsImlzc3VlZEF0IjoiMjAyNi0wMS0wMVQwMDowMDowMFoiLCJsaWNlbnNlSWQiOiJoYXJpdnUtZGV2LWxpY2Vuc2UtdjEiLCJsaWNlbnNlVmVyc2lvbiI6MSwibWFuaWZlc3RTaGEyNTYiOiJmZDM2ODM2NWMyOTA1M2M5YWRhZjkxODU3ZDJiODkxY2RhNTIwMDIxNjliZDBmNmUwZDZiMDI0YmM0ODZjOTBlIiwibm90QmVmb3JlIjoiMjAyNi0wMS0wMVQwMDowMDowMFoiLCJwdWJsaWNhdGlvbklkIjoiaGFyaXZ1LXBoYXNlMi1maXh0dXJlIiwicHVibGljYXRpb25WZXJzaW9uIjoxfQ.6tfX5R3CPoW0tEfZhEvwAChJ58lWWbC9U8fY1ZdsXD-MyBampyHru6mVhBZ_BxC5YVTf3Xn-Cid5hLzUxE0mSA"#
  private let contentKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  private let nonceHex = "000102030405060708090a0b"
  private let ciphertextHex = "7b72e853a497ab6df861e7f9de9d1d0ef7b3e314961227084d1580ab2146708c0b"
  private let tagHex = "ee706c631439e486cbc471177c7f2433"
  private let plaintext = "<p>Harivu protected fixture.</p>\n"
  private let now = ISO8601DateFormatter().date(from: "2026-11-09T00:00:00Z")!

  private func hex(_ value: String) -> Data {
    var bytes = [UInt8](); var i = value.startIndex
    while i < value.endIndex { let n = value.index(i, offsetBy: 2); bytes.append(UInt8(value[i ..< n], radix: 16)!); i = n }
    return Data(bytes)
  }

  private func assertThrows(_ expected: HarivuProtectionError, file: StaticString = #filePath, line: UInt = #line, _ block: () throws -> Void) {
    do { try block(); XCTFail("expected \(expected)", file: file, line: line) } catch {
      XCTAssertEqual(error as? HarivuProtectionError, expected, file: file, line: line)
    }
  }

  func testRecordedLicenseResolvesAndDecryptsRecordedResource() throws {
    let session = try HarivuProtectionSessionResolver().resolve(manifest: manifest, licenseJWS: license, now: now)
    XCTAssertEqual(session.contentKey.withUnsafeBytes { Data($0) }, hex(contentKeyHex))
    let resource = try XCTUnwrap(session.resources.values.first)
    XCTAssertEqual(String(data: resource.aad, encoding: .utf8), #"{"algorithm":"A256GCM","mediaType":"application/xhtml+xml","packageVersion":1,"path":"EPUB/chapter-1.xhtml","plaintextLength":33,"publicationId":"harivu-phase2-fixture","publicationVersion":1}"#)
    let out = try HarivuContentProtection.decrypt(ciphertext: hex(ciphertextHex), resource: resource, contentKey: session.contentKey)
    XCTAssertEqual(String(data: out, encoding: .utf8), plaintext)
  }

  func testChangedManifestFailsAsTampered() {
    assertThrows(.protectedPackageTampered) {
      _ = try HarivuProtectionSessionResolver().resolve(manifest: Data("{}".utf8), licenseJWS: license, now: now)
    }
  }

  func testExpiredLicenseFailsClosed() {
    let later = ISO8601DateFormatter().date(from: "2037-01-01T00:00:00Z")!
    assertThrows(.protectedLicenseExpired) {
      _ = try HarivuProtectionSessionResolver().resolve(manifest: manifest, licenseJWS: license, now: later)
    }
  }

  func testTamperedSignatureFailsAsInvalidLicense() {
    var parts = license.split(separator: ".").map(String.init)
    parts[2] = String(parts[2].dropLast(2)) + (parts[2].hasSuffix("AA") ? "BB" : "AA")
    assertThrows(.protectedLicenseInvalid) {
      _ = try HarivuProtectionSessionResolver().resolve(manifest: manifest, licenseJWS: parts.joined(separator: "."), now: now)
    }
  }

  func testChangedCiphertextTagOrNonceFailsAsTampered() throws {
    let session = try HarivuProtectionSessionResolver().resolve(manifest: manifest, licenseJWS: license, now: now)
    let resource = try XCTUnwrap(session.resources.values.first)
    var cipher = hex(ciphertextHex); cipher[0] ^= 1
    assertThrows(.protectedPackageTampered) {
      _ = try HarivuContentProtection.decrypt(ciphertext: cipher, resource: resource, contentKey: session.contentKey)
    }
    let wrongKey = SymmetricKey(data: Data(repeating: 7, count: 32))
    assertThrows(.protectedPackageTampered) {
      _ = try HarivuContentProtection.decrypt(ciphertext: self.hex(self.ciphertextHex), resource: resource, contentKey: wrongKey)
    }
  }

  func testChangedNonceFailsAsTampered() throws {
    let session = try HarivuProtectionSessionResolver().resolve(manifest: manifest, licenseJWS: license, now: now)
    let resource = try XCTUnwrap(session.resources.values.first)
    var nonce = resource.nonce; nonce[0] ^= 1
    let changed = HarivuProtectedResource(
      nonce: nonce, tag: resource.tag, aad: resource.aad, plaintextLength: resource.plaintextLength,
      ciphertextSHA256: resource.ciphertextSHA256, plaintextSHA256: resource.plaintextSHA256)
    assertThrows(.protectedPackageTampered) {
      _ = try HarivuContentProtection.decrypt(ciphertext: self.hex(self.ciphertextHex), resource: changed, contentKey: session.contentKey)
    }
  }
}
