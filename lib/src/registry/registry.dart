// See file LICENSE for more information.

library pointycastle.src.registry;

import "package:pointycastle/api.dart";
import 'package:pointycastle/src/registry/registration.dart';

final FactoryRegistry registry = _RegistryImpl();

abstract class FactoryRegistry {
  T create<T>(String registrableName);

  void register<T>(FactoryConfig config);
}

typedef /*Registrable*/ RegistrableConstructor();
typedef RegistrableConstructor DynamicConstructorFactory(
    String registrableName, Match match);

abstract class FactoryConfig {
  final Type type;

  FactoryConfig(this.type);
}

class StaticFactoryConfig extends FactoryConfig {
  final String algorithmName;
  final RegistrableConstructor factory;

  StaticFactoryConfig(Type type, this.algorithmName, this.factory)
      : super(type);
}

// From the PatternCharacter rule here:
// http://ecma-international.org/ecma-262/5.1/#sec-15.10
final _specialRegExpChars = new RegExp(r'([\\\^\$\.\|\+\[\]\(\)\{\}])');

/// Escapes special regular exppression characters in [str] so that it can be
/// used as a literal match inside of a [RegExp].
///
/// The special characters are: \ ^ $ . | + [ ] ( ) { }
/// as defined here: http://ecma-international.org/ecma-262/5.1/#sec-15.10
String _escapeRegExp(String str) => str.splitMapJoin(_specialRegExpChars,
    onMatch: (Match m) => '\\${m.group(0)}', onNonMatch: (s) => s);

class DynamicFactoryConfig extends FactoryConfig {
  final RegExp regExp;
  final DynamicConstructorFactory factory;

  DynamicFactoryConfig(Type type, this.regExp, this.factory) : super(type);

  DynamicFactoryConfig.regex(
      Type type, String regexString, DynamicConstructorFactory factory)
      : this(type, new RegExp(regexString), factory);

  /// A dynamic registry that matches by prefix.
  /// The part after the prefix will be in `match.group(1)`.
  DynamicFactoryConfig.prefix(
      Type type, String prefix, DynamicConstructorFactory factory)
      : this.regex(type, "^${_escapeRegExp(prefix)}(.+)\$", factory);

  /// A dynamic registry that matches by suffix.
  /// The part before the suffix will be in `match.group(1)`.
  DynamicFactoryConfig.suffix(
      Type type, String suffix, DynamicConstructorFactory factory)
      : this.regex(type, "^(.+)${_escapeRegExp(suffix)}\$", factory);

  /// Invokes the factory when it matches. Else returns null.
  RegistrableConstructor tryFactory(String algorithmName) {
    Match match = regExp.firstMatch(algorithmName);
    if (match == null) {
      return null;
    }
    return factory(algorithmName, match);
  }
}

class _RegistryImpl implements FactoryRegistry {
  static const int _CONSTRUCTOR_CACHE_SIZE = 25;

  final Map<Type, Map<String, RegistrableConstructor>> _staticFactories;
  final Map<Type, Set<DynamicFactoryConfig>> _dynamicFactories;

  final Map<String, RegistrableConstructor> _constructorCache =
      Map<String, RegistrableConstructor>();

  bool _initialized = false;

  _RegistryImpl()
      : _staticFactories = Map<Type, Map<String, RegistrableConstructor>>(),
        _dynamicFactories = Map<Type, Set<DynamicFactoryConfig>>();

  @override
  T create<T>(String registrableName) {
    Type type = T;
    RegistrableConstructor constructor = getConstructor(type, registrableName);
    T result = constructor();
    return result;
  }

  RegistrableConstructor getConstructor(Type type, String registrableName) {
    RegistrableConstructor constructor =
        _constructorCache["${type}.${registrableName}"];

    if (constructor == null) {
      constructor = _createConstructor(type, registrableName);
      if (_constructorCache.length > _CONSTRUCTOR_CACHE_SIZE) {
        _constructorCache.clear();
      }
      _constructorCache["${type}.${registrableName}"] = constructor;
    }
    return constructor;
  }

  RegistrableConstructor _createConstructor(Type type, String registrableName) {
    // Init lazily
    _checkInit();

    if (_staticFactories.containsKey(type) &&
        _staticFactories[type].containsKey(registrableName)) {
      return _staticFactories[type][registrableName];
    }

    if (_dynamicFactories.containsKey(type)) {
      for (DynamicFactoryConfig factory in _dynamicFactories[type]) {
        RegistrableConstructor constructor =
            factory.tryFactory(registrableName);
        if (constructor != null) {
          return constructor;
        }
      }
    }

    // No factory found
    throw new RegistryFactoryException.unknown(registrableName, type);
  }

  void _checkInit() {
    if (!_initialized) {
      _initialize();
    }
  }

  @override
  void register<T>(FactoryConfig config) {
    Type t = T;
    if (config is StaticFactoryConfig) {
      _addStaticFactoryConfig(config);
    } else if (config is DynamicFactoryConfig) {
      _addDynamicFactoryConfig(config);
    }
  }

  void _addStaticFactoryConfig(StaticFactoryConfig config) {
    Map factories = _staticFactories.putIfAbsent(
        config.type, () => Map<String, RegistrableConstructor>());
    factories[config.algorithmName] = config.factory;
  }

  void _addDynamicFactoryConfig(DynamicFactoryConfig config) {
    Set factories = _dynamicFactories.putIfAbsent(
        config.type, () => Set<DynamicFactoryConfig>());
    factories.add(config);
  }

  void _initialize() {
    registerFactories(this);
    _initialized = true;
  }
}
