import 'package:kanbot/data/repositories/organizations_repository.dart';
import 'package:kanbot/domain/models/list_page.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/paged_view_model.dart';
import 'package:kanbot/utils/result.dart';

/// The organizations the user may read, a page at a time.
class OrganizationsViewModel extends PagedViewModel<OrganizationSummary> {
  OrganizationsViewModel({required this._repository});

  final OrganizationsRepository _repository;

  Loadable<List<OrganizationSummary>> get organizations => items;

  @override
  Future<Result<ListPage<OrganizationSummary>>> fetch({String? after}) =>
      _repository.list(after: after);

  Future<Result<Organization>> create(String slug, String name) =>
      _repository.create(slug: slug, name: name);
}
