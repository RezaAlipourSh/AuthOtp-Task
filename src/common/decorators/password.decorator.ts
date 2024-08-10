import {
  registerDecorator,
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidatorOptions,
} from "class-validator";

export function ConfirmPassword(
  property: string,
  vaildationOption?: ValidatorOptions
) {
  return (object: any, propertyName: string) => {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: vaildationOption,
      constraints: [property],
      validator: ConfirmedPasswordConstrains,
    });
  };
}

@ValidatorConstraint({
  name: "ConfirmedPassword",
  async: false,
})
export class ConfirmedPasswordConstrains
  implements ValidatorConstraintInterface
{
  validate(value: any, args?: ValidationArguments) {
    const { object, constraints } = args;
    const [property] = constraints;

    const relatedValue = object[property];
    return value === relatedValue;
  }
  defaultMessage(validationArguments?: ValidationArguments): string {
    return "password and confirm password not equals";
  }
}
