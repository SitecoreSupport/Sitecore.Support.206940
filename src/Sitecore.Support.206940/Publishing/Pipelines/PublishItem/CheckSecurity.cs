using Sitecore.Configuration;
using Sitecore.Data;
using Sitecore.Data.Items;
using Sitecore.Data.Managers;
using Sitecore.Diagnostics;
using Sitecore.Globalization;
using Sitecore.Publishing;
using Sitecore.Publishing.Pipelines.PublishItem;
using Sitecore.Security.AccessControl;
using Sitecore.Security.Accounts;
using Sitecore.SecurityModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Sitecore.Support.Publishing.Pipelines.PublishItem
{
  public class CheckSecurity : PublishItemProcessor
  {
    public override void Process(PublishItemContext context)
    {
      Assert.ArgumentNotNull(context, "context");
      string empty = string.Empty;
      User user = User.FromName(context.PublishOptions.UserName, true);
      if (!CanPublish(context, context.ItemId, user, ref empty))
      {
        context.AbortPipeline(PublishOperation.Skipped, PublishChildAction.Allow, empty, true);
      }
    }
    private bool CanPublish(PublishItemContext context, ID itemId, User user, ref string explanation)
    {
      Assert.ArgumentNotNull(itemId, "itemId");
      Assert.ArgumentNotNull(user, "user");
      Assert.ArgumentNotNull(explanation, "explanation");
      if (!Settings.Publishing.CheckSecurity)
      {
        return true;
      }
      if (!CanPublishLanguage(context, itemId, user, ref explanation))
      {
        return false;
      }
      Item sourceItem = context.PublishHelper.GetSourceItem(itemId);
      if (sourceItem == null)
      {
        return CanPublishDeletion(context, itemId, user, ref explanation);
      }
      return CanPublishUpdate(sourceItem, user, ref explanation);
    }

    private bool CanPublishUpdate(Item sourceItem, User user, ref string explanation)
    {
      using (new SecurityEnabler())
      {
        bool flag = AuthorizationManager.IsAllowed(sourceItem, AccessRight.ItemRead, user) && AuthorizationManager.IsAllowed(sourceItem, AccessRight.ItemWrite, user);
        if (!flag)
        {
          explanation = $"User does not have the required access. To publish an update, a user must have read and write access to the source item. User: {user.Name}, item id: {sourceItem.ID}, database: {sourceItem.Database.Name}.";
        }
        return flag;
      }
    }

    private bool CanPublishDeletion(PublishItemContext context, ID itemId, User user, ref string explanation)
    {
      if (!Settings.Publishing.RequireTargetDeleteRightWhenCheckingSecurity)
      {
        return true;
      }
      Item targetItem = context.PublishHelper.GetTargetItem(itemId);
      if (targetItem == null)
      {
        return true;
      }
      using (new SecurityEnabler())
      {
        bool flag = AuthorizationManager.IsAllowed(targetItem, AccessRight.ItemDelete, user);
        if (!flag)
        {
          explanation = $"User does not have the required access. To publish a deletion, a user must have delete access to the target item. User: {user.Name}, item id: {targetItem.ID}, database: {targetItem.Database.Name}.";
        }
        return flag;
      }
    }

    private bool CanPublishLanguage(PublishItemContext context, ID itemId, User user, ref string explanation)
    {
      Item item = null;
      item = context.PublishHelper.GetSourceItem(itemId);
      if (item == null)
      {
        item = context.PublishHelper.GetTargetItem(itemId);
      }
      if (item == null)
      {
        return true;
      }
      Item languageItem = item.TemplateID == TemplateIDs.Language
        ? item
        : LanguageManager.GetLanguageItem(item.Language, item.Database);

      if (languageItem == null)
      {
        return true;
      }

      using (new SecurityEnabler())
      {
        var allowed = AuthorizationManager.IsAllowed(languageItem, AccessRight.LanguageWrite, user);
        if (!allowed)
        {
          explanation = string.Format(
           Texts.USER_DOES_NOT_HAVE_THE_REQUIRED_ACCESS_TO_PUBLISH_A_ITEM_A_USER_MUST_HAVE_LANGUAGE_ACCESS_TO_THE_SOURCE_ITEM_ITEM_ID_0_DATABASE_1,
           user.Name,
           item.ID,
           item.Database.Name);
        }

        return allowed;
      }
    }
  }
}