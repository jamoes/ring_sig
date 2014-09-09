module ECDSA
  class Point
    alias_method :*, :multiply_by_scalar
    alias_method :+, :add_to_point
  end
end
