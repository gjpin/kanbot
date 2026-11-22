import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/paged_view_model.dart';
import 'package:kanbot/ui/features/organizations/organizations_view_model.dart';
import 'package:kanbot/ui/features/teams/teams_view_model.dart';

import '../../helpers/fake_backend.dart';
import '../../helpers/test_dependencies.dart';

const String _otherId = '55555555-5555-4555-8555-555555555555';

/// Answers `GET path` with [first] without `after`, and with [second] for
/// `after=<first's next>`; any other cursor fails the test.
void _pages(
  FakeBackend backend,
  String path,
  Map<String, Object?> first,
  Map<String, Object?> second,
) => backend.handle('GET', path, (request) {
  final after = request.url.queryParameters['after'];
  final body = switch (after) {
    null => first,
    _ when after == first['next'] => second,
    _ => fail('unexpected cursor: $after'),
  };
  return http.Response(
    jsonEncode(body),
    200,
    headers: {'content-type': 'application/json'},
  );
});

List<String?> _afters(FakeBackend backend, String path) => [
  for (final request in backend.sent('GET', path))
    request.url.queryParameters['after'],
];

/// One paged list: its path, how a page and an item look, and its
/// ViewModel over a signed-in backend.
typedef _Case = ({
  String name,
  String path,
  Map<String, Object?> Function(List<Object?> items, {String? next}) page,
  Map<String, Object?> Function(String id, String name) item,
  Future<PagedViewModel<Object?>> Function(FakeBackend backend) create,
});

void main() {
  final cases = <_Case>[
    (
      name: 'teams',
      path: '/teams',
      page: teamPage,
      item: (id, name) => teamSummary(id: id, name: name),
      create: (backend) async =>
          TeamsViewModel(repository: (await signedIn(backend)).teams),
    ),
    (
      name: 'organizations',
      path: '/organizations',
      page: organizationPage,
      item: (id, name) => {'id': id, 'slug': 'x', 'name': name},
      create: (backend) async => OrganizationsViewModel(
        repository: (await signedIn(backend)).organizations,
      ),
    ),
  ];
  for (final (:name, :path, :page, :item, :create) in cases) {
    group(name, () {
      test('loads the next page after the previous one\'s next', () async {
        final backend = FakeBackend();
        _pages(
          backend,
          path,
          page([item(orgId, 'A')], next: 'a'),
          page([item(_otherId, 'B')]),
        );
        final viewModel = await create(backend);

        await viewModel.load();
        expect(viewModel.hasMore, isTrue);
        expect(_count(viewModel), 1);

        await viewModel.loadMore();
        expect(_afters(backend, path), [null, 'a']);
        expect(_count(viewModel), 2);
        expect(viewModel.hasMore, isFalse);

        // The last page: nothing more is asked for.
        await viewModel.loadMore();
        expect(_afters(backend, path), [null, 'a']);
      });

      test('a failed next page keeps the pages loaded', () async {
        final backend = FakeBackend();
        final viewModel = await create(backend);
        backend.handle('GET', path, (request) {
          if (request.url.queryParameters['after'] == null) {
            return http.Response(
              jsonEncode(page([item(orgId, 'A')], next: 'a')),
              200,
              headers: {'content-type': 'application/json'},
            );
          }
          throw http.ClientException('down');
        });

        await viewModel.load();
        await viewModel.loadMore();

        expect(viewModel.moreError, isA<ApiNetworkException>());
        expect(_count(viewModel), 1);
        expect(viewModel.hasMore, isTrue);
        expect(viewModel.loadingMore, isFalse);
      });

      test('a page that arrives after a reload is dropped', () async {
        final backend = FakeBackend();
        final viewModel = await create(backend);
        final second = Completer<http.Response>();
        backend.handle('GET', path, (request) {
          if (request.url.queryParameters['after'] == null) {
            return http.Response(
              jsonEncode(page([item(orgId, 'A')], next: 'a')),
              200,
              headers: {'content-type': 'application/json'},
            );
          }
          return second.future;
        });
        await viewModel.load();

        final more = viewModel.loadMore();
        await pumpEventQueue();
        await viewModel.load();
        second.complete(
          http.Response(
            jsonEncode(page([item(_otherId, 'B')])),
            200,
            headers: {'content-type': 'application/json'},
          ),
        );
        await more;

        expect(_count(viewModel), 1);
        expect(viewModel.hasMore, isTrue);
      });
    });
  }
}

int _count(PagedViewModel<Object?> viewModel) => switch (viewModel.items) {
  Loaded(:final value) => value.length,
  _ => fail('not loaded'),
};
