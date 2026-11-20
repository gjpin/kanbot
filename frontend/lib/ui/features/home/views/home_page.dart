import 'package:flutter/widgets.dart';
import 'package:shad/shad.dart';

/// Placeholder home page: a counter.
class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int _counter = 0;

  @override
  Widget build(BuildContext context) {
    final theme = ShadTheme.of(context);
    return Center(
      child: ShadColumn(
        mainAxisSize: .min,
        spacing: 4,
        children: [
          Text(
            'You have pushed the button this many times:',
            style: theme.textTheme.muted,
          ),
          Text('$_counter', style: theme.textTheme.h1),
          ShadButton(
            onPressed: () => setState(() => _counter++),
            child: const Icon(LucideIcons.plus),
          ),
        ],
      ),
    );
  }
}
