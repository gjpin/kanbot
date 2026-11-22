import 'package:kanbot/data/repositories/organizations_repository.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// The organizations the user may read.
class OrganizationsViewModel extends ViewModel {
  OrganizationsViewModel({required this._repository});

  final OrganizationsRepository _repository;

  Loadable<List<OrganizationSummary>> _organizations = const Loading();

  Loadable<List<OrganizationSummary>> get organizations => _organizations;

  Future<void> load() async {
    _organizations = const Loading();
    notifyListeners();
    _organizations = switch (await _repository.list()) {
      Ok(:final value) => Loaded(value),
      Failure(:final error) => LoadFailed(error),
    };
    notifyListeners();
  }

  Future<Result<Organization>> create(String slug, String name) =>
      _repository.create(slug: slug, name: name);
}
